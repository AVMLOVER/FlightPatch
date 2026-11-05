static BOOL nt6_existing(SppPlan *plan, const wchar_t *root)
{
    wchar_t pattern[PATH_SIZE];
    if (!spp_path_type(root, TRUE, FALSE))
        return spp_path_type(root, TRUE, TRUE);
    if (!spp_add_directory(plan, root, TRUE) || !build_path(pattern, root, L"*"))
        return FALSE;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    BOOL ok = TRUE;
    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
            continue;
        wchar_t path[PATH_SIZE];
        if (!build_path(path, root, data.cFileName)) {
            ok = FALSE;
            break;
        }
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ok = spp_path_type(path, TRUE, FALSE) && nt6_existing(plan, path);
        } else {
            BOOL included = FALSE;
            for (size_t i = 0; i < plan->count; ++i)
                included |= !_wcsicmp(path, plan->files[i].target);
            if (!included)
                ok = spp_add_file(plan, path, path, FALSE, TRUE, 0);
        }
    } while (ok && FindNextFileW(find, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = FALSE;
    FindClose(find);
    return ok;
}

static BOOL nt6_tree(SppPlan *plan, const wchar_t *donor, const wchar_t *target,
                     const wchar_t *relative, BOOL trustedinstaller)
{
    if (!spp_path_chain(donor, TRUE) || !spp_path_chain(target, FALSE) ||
        !_wcsicmp(donor, target) || offline_under(donor, target) || offline_under(target, donor))
        return FALSE;
    size_t files = plan->count, directories = plan->dir_count;
    if (!spp_add_directory(plan, target, TRUE) ||
        !spp_collect(plan, donor, target, relative, FALSE, 0) ||
        (!trustedinstaller && plan->count == files) || !nt6_existing(plan, target))
        return FALSE;
    for (size_t i = files; i < plan->count; ++i)
        plan->files[i].trustedinstaller = trustedinstaller;
    for (size_t i = directories; i < plan->dir_count; ++i)
        plan->directories[i].trustedinstaller = trustedinstaller;
    return TRUE;
}

static BOOL nt6_branding(const wchar_t *source, wchar_t branding[PATH_SIZE])
{
    const wchar_t *layouts[] = {L"Branding", L"Windows\\Branding"};
    branding[0] = L'\0';
    for (unsigned i = 0; i < sizeof layouts / sizeof *layouts; ++i) {
        wchar_t path[PATH_SIZE];
        if (!build_path(path, source, layouts[i]) || !spp_path_type(path, TRUE, TRUE))
            return FALSE;
        if (!spp_path_type(path, TRUE, FALSE))
            continue;
        if (branding[0]) {
            fwprintf(stderr, L"More than one Branding donor directory. Supply only one.\n");
            return FALSE;
        }
        wcscpy(branding, path);
    }
    return TRUE;
}

static BOOL replace_nt6_tokens(const wchar_t *source, const wchar_t *target)
{
    static const wchar_t *const layouts[] = {
        L"Windows\\System32\\spp\\tokens", L"System32\\spp\\tokens", L"spp\\tokens", L"tokens"
    };
    wchar_t donor[PATH_SIZE] = {0}, destination[PATH_SIZE];
    unsigned matches = 0;
    for (unsigned i = 0; i < sizeof layouts / sizeof *layouts; ++i) {
        wchar_t path[PATH_SIZE];
        if (!build_path(path, source, layouts[i]))
            return FALSE;
        if (spp_path_type(path, TRUE, FALSE)) {
            if (!spp_path_chain(path, TRUE))
                return FALSE;
            wcscpy(donor, path);
            ++matches;
        }
    }
    const wchar_t *leaf = wcsrchr(source, L'\\');
    if (leaf && !_wcsicmp(leaf + 1, L"tokens")) {
        wcscpy(donor, source);
        ++matches;
    }
    if (matches != 1 || !spp_path_chain(donor, TRUE) ||
        !build_path(destination, target, L"Windows\\System32\\spp\\tokens") ||
        !spp_path_chain(destination, FALSE) || !_wcsicmp(donor, destination) ||
        offline_under(donor, destination) || offline_under(destination, donor)) {
        fwprintf(stderr, L"Specify one separate donor tokens folder, its spp parent, or its Windows image root.\n");
        return FALSE;
    }
    wchar_t branding[PATH_SIZE];
    SppPlan plan = {.mode = SPP_NT6};
    BOOL ok = nt6_branding(source, branding) && nt6_tree(&plan, donor, destination, L"spp\\tokens", FALSE);
    size_t tokens = plan.count;
    if (ok && branding[0])
        ok = build_path(destination, target, L"Windows\\Branding") &&
             nt6_tree(&plan, branding, destination, L"Branding", TRUE) &&
             ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                                    &plan.owner_sid);
    if (ok)
        ok = ConvertStringSidToSidW(L"S-1-5-80-123231216-2592883651-3715271367-3753151631-4175906628",
                                    &plan.service_sid) && spp_apply(&plan);
    if (ok) {
        wprintf(L"NT6 tokens updated. SPPSVC has full control on the tokens tree (%zu files).\n", tokens);
        if (branding[0])
            wprintf(L"Windows\\Branding updated with TrustedInstaller Full Control (%zu files).\n", plan.count - tokens);
    }
    LocalFree(plan.owner_sid);
    LocalFree(plan.service_sid);
    free(plan.files);
    free(plan.directories);
    return ok;
}
