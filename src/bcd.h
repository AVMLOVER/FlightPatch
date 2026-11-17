/* The target entry needs nointegritychecks on, otherwise the patched loader
   refuses the modified ci.dll with 0xc0000428. These helpers drive bcdedit
   against an offline BCD store on a supplied EFI System Partition. */

/* An EFI System Partition keeps the store at EFI\Microsoft\Boot\BCD; an extracted
   installation medium also carries the BIOS store at boot\bcd. Both are serviced so a
   media tree can be prepared in one step. */
static unsigned bcd_stores(const wchar_t *root, wchar_t stores[2][PATH_SIZE])
{
    static const wchar_t *const names[2] = {L"EFI\\Microsoft\\Boot\\BCD", L"boot\\bcd"};
    unsigned count = 0;
    for (unsigned i = 0; i < 2; ++i) {
        wchar_t path[PATH_SIZE];
        if (build_path(path, root, names[i]) && spp_path_type(path, FALSE, FALSE)) {
            wcscpy(stores[count], path);
            ++count;
        }
    }
    return count;
}

static BOOL bcd_store(const wchar_t *esp, wchar_t store[PATH_SIZE])
{
    wchar_t stores[2][PATH_SIZE];
    unsigned count = bcd_stores(esp, stores);
    if (!count) {
        fwprintf(stderr, L"No EFI\\Microsoft\\Boot\\BCD or boot\\bcd under %ls. "
                         L"Point this at the EFI System Partition or a media root.\n", esp);
        return FALSE;
    }
    wcscpy(store, stores[0]);
    return TRUE;
}

/* bcdedit may not be reachable through lpApplicationName alone (WinPE has a
   trimmed PATH, and a 32-bit host sees System32 redirected), so resolve it. */
static BOOL bcd_tool(wchar_t tool[PATH_SIZE])
{
    wchar_t folder[PATH_SIZE];
    UINT length = GetSystemDirectoryW(folder, PATH_SIZE);
    if (length && length < PATH_SIZE && build_path(tool, folder, L"bcdedit.exe") &&
        GetFileAttributesW(tool) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    length = GetWindowsDirectoryW(folder, PATH_SIZE);
    if (length && length < PATH_SIZE && build_path(tool, folder, L"System32\\bcdedit.exe") &&
        GetFileAttributesW(tool) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    DWORD found = SearchPathW(NULL, L"bcdedit.exe", NULL, PATH_SIZE, tool, NULL);
    if (found && found < PATH_SIZE)
        return TRUE;
    fwprintf(stderr, L"Cannot locate bcdedit.exe. Run the command it prints by hand from a full "
                     L"Windows or a WinPE that has bcdedit.\n");
    return FALSE;
}

/* Set one element on one entry of the offline store. */
static BOOL bcd_element(const wchar_t *store, const wchar_t *tool, const wchar_t *guid,
                        const wchar_t *element, const wchar_t *value)
{
    wchar_t command[600];
    if (swprintf(command, ARRAYSIZE(command), L"\"%ls\" /store \"%ls\" /set %ls %ls %ls",
                 tool, store, guid, element, value) < 0)
        return FALSE;
    wprintf(L"%ls\n", command);
    return run_tool(tool, command, NULL);
}

/* The CI patch needs nointegritychecks, and turning recovery off keeps a failed
   attempt in the boot menu instead of starting the automatic repair. */
static BOOL bcd_set_nointegritychecks(const wchar_t *esp, const wchar_t *guid)
{
    wchar_t stores[2][PATH_SIZE], tool[PATH_SIZE];
    unsigned count = bcd_stores(esp, stores);
    if (!count || !bcd_tool(tool))
        return FALSE;
    BOOL ok = TRUE;
    for (unsigned i = 0; i < count; ++i) {
        if (!bcd_element(stores[i], tool, guid, L"nointegritychecks", L"on")) {
            ok = FALSE;
            continue;
        }
        if (!bcd_element(stores[i], tool, guid, L"recoveryenabled", L"No"))
            fwprintf(stderr, L"recoveryenabled was not set in %ls; the CI option is still in place.\n",
                     stores[i]);
        wprintf(L"nointegritychecks is on and recovery is off for %ls in %ls.\n", guid, stores[i]);
    }
    return ok;
}

static BOOL bcd_show(const wchar_t *esp, const wchar_t *guid)
{
    wchar_t stores[2][PATH_SIZE], tool[PATH_SIZE], command[600];
    unsigned count = bcd_stores(esp, stores);
    if (!count || !bcd_tool(tool))
        return FALSE;
    BOOL ok = TRUE;
    for (unsigned i = 0; i < count; ++i) {
        if (swprintf(command, ARRAYSIZE(command), L"\"%ls\" /store \"%ls\" /enum %ls /v",
                     tool, stores[i], guid) < 0 || !run_tool(tool, command, NULL)) {
            ok = FALSE;
            continue;
        }
        /* Print the two flags the CI patch depends on, even when the enumeration above
           does not show them (bcdedit hides defaults). */
        if (swprintf(command, ARRAYSIZE(command),
                     L"\"%ls\" /store \"%ls\" /enum %ls /v | findstr /i \"nointegritychecks recoveryenabled\"",
                     tool, stores[i], guid) > 0)
            run_tool(tool, command, NULL);
    }
    return ok;
}

/* The BCD template inside an image is what new stores are created from, so an image
   can be prepared before it is deployed. */
static BOOL bcd_template(const wchar_t *root)
{
    wchar_t windows[PATH_SIZE], template_path[PATH_SIZE], tool[PATH_SIZE];
    if (!offline_root(root, TRUE) || !build_path(windows, root, L"Windows") ||
        !build_path(template_path, root, L"Windows\\System32\\config\\BCD-Template"))
        return FALSE;
    if (GetFileAttributesW(template_path) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"No BCD template at %ls.\n", template_path);
        return FALSE;
    }
    if (!bcd_tool(tool))
        return FALSE;
    static const struct { const wchar_t *element; const wchar_t *value; } values[] = {
        {L"nointegritychecks", L"on"},
        {L"recoveryenabled", L"No"}
    };
    BOOL ok = TRUE;
    for (unsigned i = 0; i < ARRAYSIZE(values); ++i) {
        if (!bcd_element(template_path, tool, L"{default}", values[i].element, values[i].value)) {
            fwprintf(stderr, L"The template does not accept %ls; skipped.\n", values[i].element);
            ok = FALSE;
        }
    }
    if (ok)
        wprintf(L"Template updated: %ls\n", template_path);
    return ok;
}

static int run_bcd(int argc, wchar_t **argv)
{
    wchar_t esp[PATH_SIZE];
    const wchar_t *guid = L"{default}";
    BOOL show = !_wcsicmp(argv[1], L"/bcd-show");
    if ((argc != 3 && argc != 4) || !normalize(esp, argv[2]) || (argc == 4 && (!argv[3][0] || argv[3][0] == L'/'))) {
        fwprintf(stderr, L"Usage: nttimebomb %ls ESP_OR_MEDIA_ROOT [ENTRY_GUID]\n", argv[1]);
        return 2;
    }
    if (argc == 4)
        guid = argv[3];
    BOOL ok = show ? bcd_show(esp, guid) : bcd_set_nointegritychecks(esp, guid);
    return ok ? 0 : 1;
}

