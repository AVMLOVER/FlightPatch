/* Offline in-place servicing. Probe all inputs and stage WinRE before writing. */
typedef struct {
    const wchar_t *path;
    Role role;
    BOOL architecture_neutral;
} OfflineFile;

static const OfflineFile offline_windows_files[] = {
    {L"Windows\\System32\\ci.dll", CI, FALSE},
    {L"Windows\\System32\\winload.efi", LOADER, FALSE},
    {L"Windows\\System32\\winload.exe", LOADER, FALSE},
    {L"Windows\\System32\\winresume.efi", LOADER, FALSE},
    {L"Windows\\System32\\winresume.exe", LOADER, FALSE},
    {L"Windows\\System32\\hvloader.efi", HVLOADER, FALSE},
    {L"Windows\\System32\\hvloader.exe", HVLOADER, FALSE},
    {L"Windows\\System32\\Boot\\winload.efi", LOADER, FALSE},
    {L"Windows\\System32\\Boot\\winload.exe", LOADER, FALSE},
    {L"Windows\\System32\\Boot\\winresume.efi", LOADER, FALSE},
    {L"Windows\\System32\\Boot\\winresume.exe", LOADER, FALSE},
    {L"Windows\\System32\\Boot\\hvloader.efi", HVLOADER, FALSE},
    {L"Windows\\System32\\Boot\\hvloader.exe", HVLOADER, FALSE},
    {L"Windows\\Boot\\EFI\\bootmgfw.efi", BOOT, FALSE},
    {L"Windows\\Boot\\EFI\\bootmgr.efi", BOOT, FALSE},
    {L"Windows\\Boot\\EFI\\memtest.efi", BOOT, FALSE},
    {L"Windows\\Boot\\PCAT\\bootmgr", LEGACY, TRUE},
    {L"Windows\\Boot\\PCAT\\memtest.exe", BOOT, TRUE}
};

static const OfflineFile offline_boot_files[] = {
    {L"EFI\\Microsoft\\Boot\\bootmgfw.efi", BOOT, FALSE},
    {L"EFI\\Microsoft\\Boot\\bootmgr.efi", BOOT, FALSE},
    {L"EFI\\Microsoft\\Boot\\memtest.efi", BOOT, FALSE},
    {L"EFI\\Boot\\bootx64.efi", BOOT, FALSE},
    {L"EFI\\Boot\\bootia32.efi", BOOT, FALSE},
    {L"bootmgr", LEGACY, TRUE},
    {L"Boot\\memtest.exe", BOOT, TRUE}
};

enum {
    OFFLINE_WINDOWS_COUNT = sizeof offline_windows_files / sizeof offline_windows_files[0],
    OFFLINE_BOOT_COUNT = sizeof offline_boot_files / sizeof offline_boot_files[0],
    OFFLINE_MAX = OFFLINE_WINDOWS_COUNT + 2 * OFFLINE_BOOT_COUNT,
    OFFLINE_WIM_MAX = 4,
    OFFLINE_NT_PATH = MAX_PATH + 64
};

typedef struct {
    wchar_t path[PATH_SIZE];
    HANDLE file;
    BY_HANDLE_FILE_INFORMATION id;
    Role role;
    Output before, after;
    BOOL touched, writable, restore_readonly;
} OfflineEdit;

typedef struct {
    wchar_t source[PATH_SIZE], staged[PATH_SIZE], stage_dir[PATH_SIZE], replacement[PATH_SIZE], backup[PATH_SIZE];
    wchar_t final[OFFLINE_NT_PATH];
    HANDLE file;
    BY_HANDLE_FILE_INFORMATION id;
    DWORD attrs;
    BOOL owns_stage, owns_replacement, replaced;
} OfflineWim;

static BOOL offline_file_id(const BY_HANDLE_FILE_INFORMATION *left, const BY_HANDLE_FILE_INFORMATION *right)
{
    return left->dwVolumeSerialNumber == right->dwVolumeSerialNumber &&
           left->nFileIndexHigh == right->nFileIndexHigh && left->nFileIndexLow == right->nFileIndexLow;
}

static BOOL offline_path_name(HANDLE file, wchar_t path[OFFLINE_NT_PATH])
{
    DWORD size = GetFinalPathNameByHandleW(file, path, OFFLINE_NT_PATH, VOLUME_NAME_NT | FILE_NAME_NORMALIZED);
    return size && size < OFFLINE_NT_PATH;
}

static BOOL offline_under(const wchar_t *path, const wchar_t *directory)
{
    size_t length = wcslen(directory);
    return length && !_wcsnicmp(path, directory, length) &&
           (directory[length - 1] == L'\\' || path[length] == L'\\');
}

static BOOL offline_directory(const wchar_t *path, wchar_t final[OFFLINE_NT_PATH])
{
    HANDLE dir = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dir == INVALID_HANDLE_VALUE)
        return FALSE;
    BY_HANDLE_FILE_INFORMATION info;
    BOOL ok = GetFileInformationByHandle(dir, &info) && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
              offline_path_name(dir, final);
    CloseHandle(dir);
    return ok;
}

static BOOL offline_absent(DWORD error)
{
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

static BOOL offline_read(HANDLE file, Output *out, BCRYPT_ALG_HANDLE algorithm)
{
    LARGE_INTEGER size;
    DWORD read;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > MAX_IMAGE)
        return FALSE;
    out->size = (DWORD)size.QuadPart;
    out->data = malloc(out->size);
    return out->data && ReadFile(file, out->data, out->size, &read, NULL) && read == out->size &&
           digest(algorithm, out->data, out->size, out->sha);
}

static BOOL offline_probe(BCRYPT_ALG_HANDLE algorithm, const OfflineFile *spec, const wchar_t *root,
                          const wchar_t *scope, const wchar_t *live, const BY_HANDLE_FILE_INFORMATION *kernel,
                          WORD target, OfflineEdit edits[OFFLINE_MAX], unsigned *count, BOOL *found)
{
    OfflineEdit *edit = &edits[*count];
    *found = FALSE;
    if (!build_path(edit->path, root, spec->path))
        return FALSE;

    BOOL fallback = !_wcsnicmp(spec->path, L"EFI\\Boot\\", 9);
    if (fallback && ((target == IMAGE_FILE_MACHINE_AMD64) != !_wcsicmp(spec->path, L"EFI\\Boot\\bootx64.efi")))
        return TRUE;

    HANDLE file = CreateFileW(edit->path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (offline_absent(error))
            return TRUE;
        fwprintf(stderr, L"Cannot read %ls (Win32 %lu).\n", edit->path, error);
        return FALSE;
    }
    wchar_t final[OFFLINE_NT_PATH];
    BOOL ok = GetFileInformationByHandle(file, &edit->id) && offline_path_name(file, final) &&
              offline_under(final, scope) && !offline_under(final, live) &&
              (!kernel || !offline_file_id(&edit->id, kernel));
    if (!ok) {
        fwprintf(stderr, L"Unsafe offline file path %ls.\n", edit->path);
        CloseHandle(file);
        return FALSE;
    }
    for (unsigned i = 0; i < *count; ++i) {
        if (offline_file_id(&edits[i].id, &edit->id)) {
            CloseHandle(file);
            if (edits[i].role != spec->role || (!spec->architecture_neutral && edits[i].after.machine != target)) {
                fwprintf(stderr, L"Conflicting roles or architectures for linked file %ls.\n", edit->path);
                return FALSE;
            }
            *found = TRUE;
            return TRUE;
        }
    }
    ++*count;
    edit->file = file;
    edit->role = spec->role;
    if (!offline_read(file, &edit->before, algorithm)) {
        fwprintf(stderr, L"Cannot read %ls.\n", edit->path);
        return FALSE;
    }
    if (fallback) {
        static const char manager[] = "bootmgfw.pdb", bootmgr[] = "bootmgr.pdb";
        Image im;
        if (!image_open(&im, edit->before.data, edit->before.size) ||
            (unique_data(&im, manager, sizeof manager) == NONE && unique_data(&im, bootmgr, sizeof bootmgr) == NONE)) {
            wprintf(L"Skipped unrecognized EFI fallback %ls.\n", edit->path);
            --*count;
            CloseHandle(file);
            free(edit->before.data);
            memset(edit, 0, sizeof *edit);
            return TRUE;
        }
    }
    edit->after.size = edit->before.size;
    edit->after.data = malloc(edit->after.size);
    if (!edit->after.data)
        return FALSE;
    memcpy(edit->after.data, edit->before.data, edit->after.size);
    wprintf(L"%ls\n", edit->path);
    BOOL changed;
    ok = spec->role == LEGACY ? patch_legacy(&edit->after) :
         patch_pe(edit->after.data, edit->after.size, spec->role, &edit->after.machine, &changed);
    if (!ok || !digest(algorithm, edit->after.data, edit->after.size, edit->after.sha)) {
        fwprintf(stderr, L"Unsupported or ambiguous structure in %ls.\n", edit->path);
        return FALSE;
    }
    if (target && !spec->architecture_neutral && edit->after.machine != target) {
        fwprintf(stderr, L"Architecture mismatch in %ls.\n", edit->path);
        return FALSE;
    }
    edit->after.changed = strcmp(edit->before.sha, edit->after.sha) != 0;
    *found = TRUE;
    return TRUE;
}

static BOOL offline_readonly(HANDLE file, BOOL readonly)
{
    FILE_BASIC_INFO current;
    if (!GetFileInformationByHandleEx(file, FileBasicInfo, &current, sizeof current))
        return FALSE;
    DWORD attrs = current.FileAttributes & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN |
                  FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_SYSTEM |
                  FILE_ATTRIBUTE_TEMPORARY);
    if (readonly)
        attrs |= FILE_ATTRIBUTE_READONLY;
    FILE_BASIC_INFO change = {.FileAttributes = attrs ? attrs : FILE_ATTRIBUTE_NORMAL};
    return SetFileInformationByHandle(file, FileBasicInfo, &change, sizeof change);
}

static BOOL offline_reopen_readonly(HANDLE file, BOOL readonly)
{
    HANDLE attrs = ReOpenFile(file, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_FLAG_BACKUP_SEMANTICS);
    if (attrs == INVALID_HANDLE_VALUE)
        return FALSE;
    BOOL ok = offline_readonly(attrs, readonly);
    DWORD error = GetLastError();
    CloseHandle(attrs);
    SetLastError(error);
    return ok;
}

static BOOL offline_lock(OfflineEdit *edit, BCRYPT_ALG_HANDLE algorithm)
{
    if (edit->id.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
        if (!offline_reopen_readonly(edit->file, FALSE)) {
            fwprintf(stderr, L"Cannot clear read-only attribute on %ls (Win32 %lu).\n", edit->path, GetLastError());
            return FALSE;
        }
        edit->restore_readonly = TRUE;
    }
    HANDLE write = ReOpenFile(edit->file, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                               FILE_FLAG_BACKUP_SEMANTICS);
    if (write == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot open for writing %ls (Win32 %lu).\n", edit->path, GetLastError());
        return FALSE;
    }
    Output snapshot = {0};
    BOOL ok = offline_read(write, &snapshot, algorithm) && !strcmp(edit->before.sha, snapshot.sha);
    free(snapshot.data);
    if (!ok) {
        fwprintf(stderr, L"File changed during preflight %ls.\n", edit->path);
        CloseHandle(write);
        return FALSE;
    }
    CloseHandle(edit->file);
    edit->file = write;
    edit->writable = TRUE;
    return TRUE;
}

static BOOL offline_write(OfflineEdit *edit, const Output *data, BCRYPT_ALG_HANDLE algorithm)
{
    LARGE_INTEGER start = {.QuadPart = 0}, end = {.QuadPart = data->size};
    return SetFilePointerEx(edit->file, start, NULL, FILE_BEGIN) &&
           write_verified(edit->file, data, algorithm) &&
           SetFilePointerEx(edit->file, end, NULL, FILE_BEGIN) && SetEndOfFile(edit->file) &&
           FlushFileBuffers(edit->file);
}

static BOOL offline_winre_probe(const wchar_t *root, const wchar_t *relative, const wchar_t *scope,
                                const wchar_t *live, OfflineWim wims[OFFLINE_WIM_MAX], unsigned *count, BOOL *found)
{
    OfflineWim *wim = &wims[*count];
    *found = FALSE;
    if (!build_path(wim->source, root, relative))
        return FALSE;
    HANDLE file = CreateFileW(wim->source, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
                              OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (offline_absent(error))
            return TRUE;
        fwprintf(stderr, L"Cannot open %ls (Win32 %lu).\n", wim->source, error);
        return FALSE;
    }
    if (!GetFileInformationByHandle(file, &wim->id) || !offline_path_name(file, wim->final) ||
        !offline_under(wim->final, scope) || offline_under(wim->final, live)) {
        CloseHandle(file);
        fwprintf(stderr, L"Unsafe WinRE path %ls.\n", wim->source);
        return FALSE;
    }
    *found = TRUE;
    /* Separate hardlinked paths each need their own WIM replacement. */
    for (unsigned i = 0; i < *count; ++i)
        if (!_wcsicmp(wims[i].final, wim->final)) {
            CloseHandle(file);
            return TRUE;
        }
    wim->attrs = wim->id.dwFileAttributes;
    wim->file = file;
    ++*count;
    return TRUE;
}

static BOOL offline_winre_stage(OfflineWim *wim, BCRYPT_ALG_HANDLE algorithm, unsigned index)
{
    wchar_t volume[PATH_SIZE], name[48];
    if (!GetVolumePathNameW(wim->source, volume, PATH_SIZE) ||
        swprintf(name, sizeof name / sizeof name[0], L".flightpatch-image-%lu-%u", GetCurrentProcessId(), index) < 0 ||
        !build_path(wim->stage_dir, volume, name) || !build_path(wim->staged, wim->stage_dir, L"Winre.wim") ||
        swprintf(wim->backup, PATH_SIZE, L"%ls.%lu.bak", wim->source, GetCurrentProcessId()) < 0 ||
        swprintf(wim->replacement, PATH_SIZE, L"%ls.%lu.new.wim", wim->source, GetCurrentProcessId()) < 0 ||
        GetFileAttributesW(wim->backup) != INVALID_FILE_ATTRIBUTES || !CreateDirectoryW(wim->stage_dir, NULL)) {
        fwprintf(stderr, L"Cannot stage %ls (Win32 %lu).\n", wim->source, GetLastError());
        return FALSE;
    }
    wim->owns_stage = TRUE;
    if (!patch_winre(algorithm, wim->source, wim->staged))
        return FALSE;
    /* DISM must mount outside the outer image, but ReplaceFile must be
       performed entirely inside the destination filesystem. */
    if (!CopyFileW(wim->staged, wim->replacement, TRUE)) {
        fwprintf(stderr, L"Cannot stage WinRE replacement %ls (Win32 %lu).\n", wim->replacement, GetLastError());
        return FALSE;
    }
    wim->owns_replacement = TRUE;
    DeleteFileW(wim->staged);
    return TRUE;
}

static BOOL offline_winre_attrs(const OfflineWim *wim, BOOL restore)
{
    if (!restore && !(wim->attrs & FILE_ATTRIBUTE_READONLY))
        return TRUE;
    DWORD flags = wim->attrs & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED |
                                FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_TEMPORARY);
    if (restore)
        flags |= wim->attrs & FILE_ATTRIBUTE_READONLY;
    return SetFileAttributesW(wim->source, flags ? flags : FILE_ATTRIBUTE_NORMAL);
}

static BOOL offline_winre_install(OfflineWim *wim)
{
    /* ReplaceFile opens the source for DELETE. Keep it protected from writers
       until just before the operation and keep a copy under the backup name. */
    HANDLE current = CreateFileW(wim->source, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                 NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    BY_HANDLE_FILE_INFORMATION id;
    BOOL same = current != INVALID_HANDLE_VALUE && GetFileInformationByHandle(current, &id) &&
                offline_file_id(&wim->id, &id);
    if (current != INVALID_HANDLE_VALUE)
        CloseHandle(current);
    if (!same) {
        fwprintf(stderr, L"WinRE changed during preflight %ls.\n", wim->source);
        return FALSE;
    }
    CloseHandle(wim->file);
    wim->file = NULL;
    if (!offline_winre_attrs(wim, FALSE)) {
        fwprintf(stderr, L"Cannot set WinRE attributes %ls (Win32 %lu).\n", wim->source, GetLastError());
        return FALSE;
    }
    BOOL ok = ReplaceFileW(wim->source, wim->replacement, wim->backup, 0, NULL, NULL);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    wim->replaced = ok || GetFileAttributesW(wim->backup) != INVALID_FILE_ATTRIBUTES;
    if ((ok || !wim->replaced) && !offline_winre_attrs(wim, TRUE)) {
        error = GetLastError();
        ok = FALSE;
    }
    if (!ok)
        fwprintf(stderr, L"Cannot replace %ls (Win32 %lu).\n", wim->source, error);
    return ok;
}

static BOOL patch_offline_image(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root, const wchar_t *boot,
                                const wchar_t *recovery)
{
    wchar_t root_final[OFFLINE_NT_PATH], boot_final[OFFLINE_NT_PATH], live_final[OFFLINE_NT_PATH];
    wchar_t recovery_final[OFFLINE_NT_PATH];
    wchar_t windows[PATH_SIZE], live[PATH_SIZE], kernel_path[PATH_SIZE], windows_final[OFFLINE_NT_PATH];
    UINT live_length = GetSystemWindowsDirectoryW(live, PATH_SIZE);
    if (!live_length || live_length >= PATH_SIZE || !offline_directory(live, live_final) ||
        !offline_directory(root, root_final) || !build_path(windows, root, L"Windows") ||
        !offline_directory(windows, windows_final) || !offline_under(windows_final, root_final) ||
        !_wcsicmp(windows_final, live_final) || offline_under(windows_final, live_final) ||
        (boot && !offline_directory(boot, boot_final)) ||
        (recovery && !offline_directory(recovery, recovery_final)) ||
        !build_path(kernel_path, root, L"Windows\\System32\\ntoskrnl.exe")) {
        fwprintf(stderr, L"Provide a valid offline Windows root and optional boot or recovery volume.\n");
        return FALSE;
    }
    if (boot && !_wcsicmp(boot_final, root_final))
        boot = NULL;

    HANDLE kernel = CreateFileW(kernel_path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    BY_HANDLE_FILE_INFORMATION kernel_id;
    if (kernel != INVALID_HANDLE_VALUE) {
        BOOL ok = GetFileInformationByHandle(kernel, &kernel_id);
        CloseHandle(kernel);
        if (!ok)
            return FALSE;
    } else if (!offline_absent(GetLastError())) {
        fwprintf(stderr, L"Cannot identify the kernel to protect %ls.\n", kernel_path);
        return FALSE;
    }
    const BY_HANDLE_FILE_INFORMATION *protected_kernel = kernel != INVALID_HANDLE_VALUE ? &kernel_id : NULL;
    OfflineEdit edits[OFFLINE_MAX] = {0};
    OfflineWim wims[OFFLINE_WIM_MAX] = {0};
    unsigned count = 0, wim_count = 0;
    BOOL ok = TRUE, found, loader = FALSE, local_boot = FALSE, separate_boot = FALSE;
    WORD target = 0;
    for (unsigned i = 0; ok && i < OFFLINE_WINDOWS_COUNT; ++i) {
        const OfflineFile *spec = &offline_windows_files[i];
        ok = offline_probe(algorithm, spec, root, root_final, live_final, protected_kernel, target, edits, &count, &found);
        if (ok && i == 0) {
            ok = found;
            if (ok)
                target = edits[0].after.machine;
            else
                fwprintf(stderr, L"No ci.dll in the offline Windows root.\n");
        }
        loader |= found && spec->role == LOADER && wcsstr(spec->path, L"winload.") != NULL;
    }
    if (ok && !loader) {
        fwprintf(stderr, L"No Windows loader found in the offline image.\n");
        ok = FALSE;
    }
    for (unsigned i = 0; ok && i < OFFLINE_BOOT_COUNT; ++i) {
        ok = offline_probe(algorithm, &offline_boot_files[i], root, root_final, live_final, protected_kernel,
                           target, edits, &count, &found);
        local_boot |= found;
        if (ok && boot) {
            ok = offline_probe(algorithm, &offline_boot_files[i], boot, boot_final, live_final, protected_kernel,
                               target, edits, &count, &found);
            separate_boot |= found;
        }
    }
    if (ok)
        ok = offline_winre_probe(root, L"Windows\\System32\\Recovery\\Winre.wim", root_final, live_final, wims, &wim_count, &found) &&
             offline_winre_probe(root, L"Recovery\\WindowsRE\\Winre.wim", root_final, live_final, wims, &wim_count, &found);
    if (ok && boot) {
        ok = offline_winre_probe(boot, L"Recovery\\WindowsRE\\Winre.wim", boot_final, live_final, wims, &wim_count, &found);
        if (ok && !separate_boot && !found) {
            fwprintf(stderr, L"No Windows boot or recovery files found on the specified /boot volume.\n");
            ok = FALSE;
        }
    }
    if (ok && recovery) {
        ok = offline_winre_probe(recovery, L"Recovery\\WindowsRE\\Winre.wim", recovery_final, live_final, wims, &wim_count, &found);
        if (ok && !found) {
            fwprintf(stderr, L"No Recovery\\WindowsRE\\Winre.wim found on the specified /recovery volume.\n");
            ok = FALSE;
        }
    }
    for (unsigned i = 0; ok && i < count; ++i)
        if (edits[i].after.changed)
            ok = offline_lock(&edits[i], algorithm);
    for (unsigned i = 0; ok && i < wim_count; ++i)
        ok = offline_winre_stage(&wims[i], algorithm, i);
    for (unsigned i = 0; ok && i < count; ++i) {
        if (!edits[i].after.changed)
            continue;
        edits[i].touched = TRUE;
        ok = offline_write(&edits[i], &edits[i].after, algorithm);
        if (!ok)
            fwprintf(stderr, L"Failed to write and verify %ls.\n", edits[i].path);
    }
    for (unsigned i = 0; ok && i < wim_count; ++i)
        ok = offline_winre_install(&wims[i]);

    for (unsigned i = wim_count; i > 0; --i) {
        OfflineWim *wim = &wims[i - 1];
        if (wim->file)
            CloseHandle(wim->file);
        if (wim->replaced) {
            if (ok) {
                if (wim->attrs & FILE_ATTRIBUTE_READONLY)
                    SetFileAttributesW(wim->backup, FILE_ATTRIBUTE_NORMAL);
                if (!DeleteFileW(wim->backup))
                    fwprintf(stderr, L"Original WinRE backup remains at %ls.\n", wim->backup);
            } else if ((GetFileAttributesW(wim->source) != INVALID_FILE_ATTRIBUTES && !offline_winre_attrs(wim, FALSE)) ||
                       !MoveFileExW(wim->backup, wim->source, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) ||
                       !offline_winre_attrs(wim, TRUE)) {
                fwprintf(stderr, L"Check WinRE rollback %ls (backup %ls).\n", wim->source, wim->backup);
            }
        }
        if (wim->owns_stage) {
            DeleteFileW(wim->staged);
            if (!RemoveDirectoryW(wim->stage_dir))
                fwprintf(stderr, L"Check the staging directory %ls.\n", wim->stage_dir);
        }
        if (wim->owns_replacement)
            DeleteFileW(wim->replacement);
    }
    BOOL metadata_ok = TRUE;
    for (unsigned i = count; i > 0; --i) {
        OfflineEdit *edit = &edits[i - 1];
        if (!ok && edit->touched && !offline_write(edit, &edit->before, algorithm))
            fwprintf(stderr, L"Could not restore %ls.\n", edit->path);
        if (edit->restore_readonly && !(edit->writable ? offline_readonly(edit->file, TRUE) :
                                                       offline_reopen_readonly(edit->file, TRUE))) {
            fwprintf(stderr, L"Could not restore read-only attribute on %ls (Win32 %lu).\n", edit->path, GetLastError());
            metadata_ok = FALSE;
        }
        CloseHandle(edit->file);
        free(edit->after.data);
        free(edit->before.data);
    }
    ok = ok && metadata_ok;
    if (ok) {
        wprintf(L"Verified offline updates in %ls.\n", root);
        if (!wim_count)
            wprintf(L"No Winre.wim found on the supplied volumes.\n");
        if (!local_boot && !separate_boot)
            wprintf(L"For an already deployed system, use /boot to include its separate boot volume.\n");
    }
    return ok;
}
