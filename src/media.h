static BOOL run_tool(const wchar_t *tool, wchar_t *command, const wchar_t *directory)
{
    STARTUPINFOW startup = {.cb = sizeof startup};
    PROCESS_INFORMATION process;
    if (!CreateProcessW(tool, command, NULL, NULL, FALSE, 0, NULL, directory, &startup, &process)) {
        fwprintf(stderr, L"Cannot launch %ls (Win32 %lu).\n", tool, GetLastError());
        return FALSE;
    }
    DWORD code = 1;
    BOOL ok = WaitForSingleObject(process.hProcess, INFINITE) == WAIT_OBJECT_0 &&
              GetExitCodeProcess(process.hProcess, &code) && code == 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!ok)
        fwprintf(stderr, L"%ls failed (exit %lu).\n", tool, code);
    return ok;
}

static BOOL find_tool(wchar_t path[PATH_SIZE], const wchar_t *option, const wchar_t *name)
{
    if (option)
        return normalize(path, option) && spp_path_type(path, FALSE, FALSE);
    DWORD n = GetModuleFileNameW(NULL, path, PATH_SIZE);
    wchar_t *slash = n && n < PATH_SIZE ? wcsrchr(path, L'\\') : NULL;
    if (!slash)
        return FALSE;
    slash[1] = L'\0';
    wchar_t folder[PATH_SIZE];
    wcscpy(folder, path);
    if (build_path(path, folder, name) && spp_path_type(path, FALSE, FALSE))
        return TRUE;
    n = SearchPathW(NULL, name, NULL, PATH_SIZE, path, NULL);
    if (n && n < PATH_SIZE)
        return TRUE;
    fwprintf(stderr, L"Provide %ls beside the program, in PATH, or with its explicit option.\n", name);
    return FALSE;
}

/* Validate every staged path. Supply destination to copy into a new tree. */
static BOOL media_tree(const wchar_t *source, const wchar_t *destination)
{
    wchar_t pattern[PATH_SIZE];
    if (!spp_path_chain(source, TRUE) || !build_path(pattern, source, L"*"))
        return FALSE;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    BOOL ok = TRUE;
    do {
        if (!wcscmp(data.cFileName, L".") || !wcscmp(data.cFileName, L".."))
            continue;
        wchar_t src[PATH_SIZE], dst[PATH_SIZE];
        ok = build_path(src, source, data.cFileName) &&
             (!destination || build_path(dst, destination, data.cFileName));
        if (!ok)
            break;
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            ok = spp_path_type(src, TRUE, FALSE) && (!destination || CreateDirectoryW(dst, NULL)) &&
                 media_tree(src, destination ? dst : NULL);
        else
            ok = spp_path_type(src, FALSE, FALSE) && (!destination ||
                 (CopyFileW(src, dst, TRUE) && SetFileAttributesW(dst,
                  data.dwFileAttributes & ~(FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_REPARSE_POINT))));
    } while (ok && FindNextFileW(find, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = FALSE;
    FindClose(find);
    return ok;
}

static BOOL root_boot_files(BCRYPT_ALG_HANDLE algorithm, const wchar_t *source, const wchar_t *output)
{
    Output images[FILE_COUNT] = {0};
    BOOL ok = TRUE;
    const unsigned indexes[] = {3, 7}; /* bootmgr.efi and Legacy bootmgr */
    for (unsigned i = 0; ok && i < 2; ++i) {
        unsigned index = indexes[i];
        ok = prepare(algorithm, source, &files[index], FALSE, &images[index]) && images[index].data;
    }
    if (ok)
        ok = write_output(output, images, algorithm);
    for (unsigned i = 0; i < FILE_COUNT; ++i)
        free(images[i].data);
    return ok;
}

static BOOL media_root_boot(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root)
{
    wchar_t input[PATH_SIZE], folder[PATH_SIZE], version[24];
    if (!build_path(input, root, L"bootmgr.efi") ||
        !build_path(folder, root, L".nttimebomb-root") || !spp_path_type(input, FALSE, FALSE))
        return FALSE;
    if (!spp_kernel_version(input, version, TRUE))
        return FALSE;
    if (wcstoul(version, NULL, 10) >= 15058) {
        wprintf(L"Newer media boot manager: preserving root boot files.\n");
        return TRUE;
    }
    if (!root_boot_files(algorithm, root, folder))
        return FALSE;
    const wchar_t *names[] = {L"bootmgr", L"bootmgr.efi"};
    BOOL ok = TRUE;
    for (unsigned i = 0; ok && i < 2; ++i) {
        wchar_t src[PATH_SIZE], dst[PATH_SIZE];
        ok = build_path(src, folder, names[i]) && build_path(dst, root, names[i]) &&
             MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (ok)
        ok = RemoveDirectoryW(folder);
    return ok;
}

static BOOL build_media_iso(const wchar_t *oscdimg, const wchar_t *work,
                            const wchar_t *partial, const wchar_t *output)
{
    static const char entries[] = "bootmgr\r\nbootmgr.efi\r\nboot\\bcd\r\nboot\\boot.sdi\r\nsources\\boot.wim\r\n";
    wchar_t order[PATH_SIZE], command[8 * PATH_SIZE];
    if (swprintf(order, PATH_SIZE, L"%ls.order.txt", work) < 0)
        return FALSE;
    HANDLE file = CreateFileW(order, GENERIC_WRITE, 0, NULL, CREATE_NEW, 0, NULL);
    DWORD written;
    BOOL ok = file != INVALID_HANDLE_VALUE && WriteFile(file, entries, sizeof entries - 1, &written, NULL) &&
              written == sizeof entries - 1;
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok)
        return FALSE;
    /* Relative boot paths keep -bootdata valid even when the workspace has spaces. */
    int n = swprintf(command, sizeof command / sizeof *command,
        L"\"%ls\" -m -o -h -u2 -udfver102 -yo\"%ls\" "
        L"-bootdata:2#p0,e,bboot\\etfsboot.com#pEF,e,befi\\microsoft\\boot\\efisys.bin . \"%ls\"",
        oscdimg, order, partial);
    ok = n > 0 && run_tool(oscdimg, command, work);
    DeleteFileW(order);
    return ok && MoveFileExW(partial, output, MOVEFILE_WRITE_THROUGH);
}

static BOOL service_media(const wchar_t *source, const wchar_t *work, const wchar_t *output,
                          const wchar_t *oscdimg_option, const wchar_t *sevenzip_option,
                          ImageOptions *options)
{
    wchar_t oscdimg[PATH_SIZE], sevenzip[PATH_SIZE], command[8 * PATH_SIZE];
    wchar_t staged[PATH_SIZE], bootsector[PATH_SIZE], efi[PATH_SIZE], partial[PATH_SIZE];
    if (!find_tool(oscdimg, oscdimg_option, L"oscdimg.exe") ||
        !_wcsicmp(source, work) || offline_under(work, source) || offline_under(source, work) ||
        !_wcsicmp(output, source) || !_wcsicmp(output, work) ||
        !spp_ext(output, (const wchar_t *const[]){L".iso", NULL}) ||
        offline_under(output, work) || offline_under(output, source) ||
        !spp_path_chain(work, FALSE) || !spp_path_chain(output, FALSE) ||
        GetFileAttributesW(work) != INVALID_FILE_ATTRIBUTES || !spp_missing(GetLastError()) ||
        GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES || !spp_missing(GetLastError()) ||
        swprintf(partial, PATH_SIZE, L"%ls.partial-%lu.iso", output, GetCurrentProcessId()) < 0 ||
        GetFileAttributesW(partial) != INVALID_FILE_ATTRIBUTES || !spp_missing(GetLastError()))
        return FALSE;
    BOOL iso = spp_ext(source, (const wchar_t *const[]){L".iso", NULL});
    if (iso && !find_tool(sevenzip, sevenzip_option, L"7z.exe"))
        return FALSE;
    if (!CreateDirectoryW(work, NULL))
        return FALSE;
    BOOL ok;
    if (iso) {
        int n = swprintf(command, sizeof command / sizeof *command,
                         L"\"%ls\" x -y -aoa \"-x![BOOT]\" -o\"%ls\" \"%ls\"", sevenzip, work, source);
        ok = n > 0 && spp_path_type(source, FALSE, FALSE) && run_tool(sevenzip, command, NULL) &&
             media_tree(work, NULL);
    } else {
        ok = media_tree(source, work);
    }
    if (ok)
        ok = build_path(bootsector, work, L"boot\\etfsboot.com") &&
             build_path(efi, work, L"efi\\microsoft\\boot\\efisys.bin") &&
             spp_path_type(bootsector, FALSE, FALSE) && spp_path_type(efi, FALSE, FALSE);
    /* The stage is private. Publish an ISO only after both WIMs and the roots pass. */
    const wchar_t *names[] = {L"sources\\boot.wim", L"sources\\install.wim"};
    for (unsigned i = 0; ok && i < 2; ++i) {
        wchar_t input[PATH_SIZE];
        ok = build_path(input, work, names[i]) && build_path(staged, work, L".nttimebomb-updated.wim");
        DWORD count = ok ? wim_image_count(input) : 0;
        if (!count) {
            fwprintf(stderr, L"Expected standalone sources\\boot.wim and sources\\install.wim.\n");
            ok = FALSE;
            break;
        }
        options->boot_wim = i == 0;
        const wchar_t *donor = options->source;
        if (i == 0)
            options->source = NULL;
        ok = edit_wim(input, staged, 1, count, service_image, options);
        options->source = donor;
        if (ok)
            ok = MoveFileExW(staged, input, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
    }
    if (ok)
        ok = media_root_boot(options->algorithm, work);
    if (ok)
        ok = build_media_iso(oscdimg, work, partial, output);
    if (!ok) {
        fwprintf(stderr, L"Media processing failed. Inspect the private workspace %ls. Any ISO output may be incomplete.\n", work);
        return FALSE;
    }
    wprintf(L"Completed all boot.wim/install.wim indexes and media boot files. ISO: %ls\n", output);
    return TRUE;
}
