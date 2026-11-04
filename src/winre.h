/* DISM services a private WIM copy. The source is opened only for copying. */
static const File winre_files[] = {
    {L"ci.dll", L"Windows\\System32\\ci.dll", CI, TRUE},
    {L"winload.efi", L"Windows\\System32\\winload.efi", LOADER, FALSE},
    {L"winload.exe", L"Windows\\System32\\winload.exe", LOADER, FALSE},
    {L"Boot\\winload.efi", L"Windows\\System32\\Boot\\winload.efi", LOADER, FALSE},
    {L"Boot\\winload.exe", L"Windows\\System32\\Boot\\winload.exe", LOADER, FALSE}
};

static BOOL scan_winre(BCRYPT_ALG_HANDLE algorithm, const wchar_t *mount, BOOL patch)
{
    enum { COUNT = sizeof winre_files / sizeof winre_files[0] };
    Output images[COUNT] = {0};
    BOOL ok = TRUE, loader = FALSE;
    for (unsigned i = 0; i < COUNT; ++i) {
        if (!prepare(algorithm, mount, &winre_files[i], TRUE, &images[i])) {
            ok = FALSE;
            break;
        }
        if (images[i].data && images[i].machine != images[0].machine) {
            fwprintf(stderr, L"WinRE file %ls does not match the target architecture.\n", winre_files[i].name);
            ok = FALSE;
            break;
        }
        if (i && images[i].data)
            loader = TRUE;
    }
    if (ok && !loader) {
        fwprintf(stderr, L"No WinRE loader was found.\n");
        ok = FALSE;
    }
    for (unsigned i = 0; patch && ok && i < COUNT; ++i) {
        if (!images[i].changed)
            continue;
        wchar_t path[PATH_SIZE];
        build_path(path, mount, winre_files[i].image_path);
        HANDLE file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        ok = file != INVALID_HANDLE_VALUE && write_verified(file, &images[i], algorithm);
        if (!ok)
            fwprintf(stderr, L"Cannot write and verify %ls (Win32 %lu).\n", path, GetLastError());
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
    }
    for (unsigned i = 0; i < COUNT; ++i)
        free(images[i].data);
    return ok;
}

static BOOL dism(const wchar_t *stage, const wchar_t *options, const wchar_t *mount,
                 const wchar_t *wim, DWORD index)
{
    wchar_t path[PATH_SIZE], system[PATH_SIZE], command[5 * PATH_SIZE];
    BOOL wow = FALSE;
    BOOL native_path = sizeof(void *) == 4 && IsWow64Process(GetCurrentProcess(), &wow) && wow;
    UINT length = native_path ? GetSystemWindowsDirectoryW(system, PATH_SIZE) :
                                GetSystemDirectoryW(system, PATH_SIZE);
    if (!length || length >= PATH_SIZE ||
        !build_path(path, system, native_path ? L"Sysnative\\dism.exe" : L"dism.exe"))
        return FALSE;
    int written;
    if (wim)
        written = swprintf(command, sizeof command / sizeof command[0],
                           L"\"%ls\" /English /ScratchDir:\"%ls\" /Mount-Image /Index:%lu "
                           L"/ImageFile:\"%ls\" /MountDir:\"%ls\" %ls", path, stage, index, wim, mount, options);
    else
        written = swprintf(command, sizeof command / sizeof command[0],
                           L"\"%ls\" /English /ScratchDir:\"%ls\" /Unmount-Image /MountDir:\"%ls\" %ls",
                           path, stage, mount, options);
    if (written < 0)
        return FALSE;
    STARTUPINFOW startup = {.cb = sizeof startup};
    PROCESS_INFORMATION process;
    fflush(stdout);
    if (!CreateProcessW(path, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
        fwprintf(stderr, L"Cannot start DISM (Win32 %lu).\n", GetLastError());
        return FALSE;
    }
    DWORD status = 1;
    BOOL ok = WaitForSingleObject(process.hProcess, INFINITE) == WAIT_OBJECT_0 &&
              GetExitCodeProcess(process.hProcess, &status) && status == 0;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!ok) {
        fwprintf(stderr, L"DISM failed (0x%08lX).\n", status);
        if (status == ERROR_ELEVATION_REQUIRED || status == ERROR_ACCESS_DENIED || status == 0x80070005u)
            privilege_hint();
    }
    return ok;
}

typedef BOOL (*WimEdit)(const wchar_t *mount, void *context);

static DWORD wim_image_count(const wchar_t *path)
{
    BYTE header[48];
    DWORD read;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    BOOL ok = ReadFile(file, header, sizeof header, &read, NULL) && read == sizeof header &&
              !memcmp(header, "MSWIM\0\0\0", 8) && u32(header + 8) >= sizeof header &&
              u16(header + 40) == 1 && u16(header + 42) == 1;
    CloseHandle(file);
    return ok ? u32(header + 44) : 0;
}

static BOOL edit_wim(const wchar_t *input, const wchar_t *output, DWORD first, DWORD last,
                     WimEdit edit, void *context)
{
    wchar_t stage[PATH_SIZE], mount[PATH_SIZE], wim[PATH_SIZE];
    size_t input_len = wcslen(input), output_len = wcslen(output);
    if (input_len < 5 || output_len < 5 || _wcsicmp(input + input_len - 4, L".wim") ||
        _wcsicmp(output + output_len - 4, L".wim") ||
        GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES ||
        swprintf(stage, PATH_SIZE, L"%.3ls.flightpatch-wim-%lu", output, GetCurrentProcessId()) < 0 ||
        !build_path(mount, stage, L"mount") || !build_path(wim, stage, L"image.wim")) {
        fwprintf(stderr, L"Provide a source WIM and a new .wim output path.\n");
        return FALSE;
    }
    if (!CreateDirectoryW(stage, NULL)) {
        fwprintf(stderr, L"Cannot create %ls (Win32 %lu).\n", stage, GetLastError());
        return FALSE;
    }
    BOOL ok = CreateDirectoryW(mount, NULL) && CopyFileW(input, wim, TRUE) &&
              SetFileAttributesW(wim, FILE_ATTRIBUTE_NORMAL);
    if (!ok)
        fwprintf(stderr, L"Cannot stage the WIM (Win32 %lu).\n", GetLastError());
    for (DWORD index = first; ok; ++index) {
        if (!(ok = dism(stage, L"/CheckIntegrity", mount, wim, index)))
            break;
        ok = edit(mount, context) && dism(stage, L"/Commit /CheckIntegrity", mount, NULL, 0);
        if (!ok) {
            if (!dism(stage, L"/Discard", mount, NULL, 0)) {
                fwprintf(stderr, L"DISM may still have the staging image mounted at %ls.\n", mount);
                return FALSE;
            }
        }
        if (index == last)
            break;
    }
    if (ok && !(ok = MoveFileExW(wim, output, MOVEFILE_WRITE_THROUGH))) {
        fwprintf(stderr, L"Cannot publish %ls (Win32 %lu).\n", output, GetLastError());
    }
    DeleteFileW(wim);
    RemoveDirectoryW(mount);
    if (!RemoveDirectoryW(stage))
        fwprintf(stderr, L"Check the staging directory %ls.\n", stage);
    if (ok)
        wprintf(L"Verified WIM copy saved in %ls.\n", output);
    return ok;
}

static BOOL edit_winre(const wchar_t *mount, void *context)
{
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");
    return scan_winre(*(BCRYPT_ALG_HANDLE *)context, mount, TRUE);
}

static BOOL patch_winre(BCRYPT_ALG_HANDLE algorithm, const wchar_t *input, const wchar_t *output)
{
    return edit_wim(input, output, 1, 1, edit_winre, &algorithm);
}
