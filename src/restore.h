/* /restore - put the retained originals back.

   Every mode writes a verified copy of the original beside the file it changes,
   as FILE.bak with the original owner, DACL and attributes.  A backup written
   by an earlier package under FILE.nttp-original is also accepted.  Restore
   writes those bytes back, re-applies the retained metadata, verifies the
   result and removes the backup. */

typedef struct {
    unsigned restored, absent, failed;
} RestoreCount;

/* Which command wrote the file decides which set a restore clears. RESTORE_ALL
   covers every file the package can change. */
enum { RESTORE_ALL, RESTORE_CI, RESTORE_LOADER, RESTORE_CERT };

typedef struct {
    const wchar_t *relative;   /* below an offline Windows root or a boot volume */
    const wchar_t *leaf;       /* inside a folder of extracted files */
    unsigned set;
} KnownOriginal;

/* Every file the patch modes can change. Restore only touches a file that has a
   retained original beside it. */
static const KnownOriginal known_originals[] = {
    {L"Windows\\System32\\ci.dll", L"ci.dll", RESTORE_CI},
    {L"Windows\\System32\\winload.efi", L"winload.efi", RESTORE_LOADER},
    {L"Windows\\System32\\winresume.efi", L"winresume.efi", RESTORE_LOADER},
    {L"Windows\\System32\\winload.exe", L"winload.exe", RESTORE_LOADER},
    {L"Windows\\System32\\winresume.exe", L"winresume.exe", RESTORE_LOADER},
    {L"Windows\\System32\\Boot\\winload.efi", L"Boot\\winload.efi", RESTORE_LOADER},
    {L"Windows\\System32\\Boot\\winresume.efi", L"Boot\\winresume.efi", RESTORE_LOADER},
    {L"Windows\\System32\\Boot\\winload.exe", L"Boot\\winload.exe", RESTORE_LOADER},
    {L"Windows\\System32\\Boot\\winresume.exe", L"Boot\\winresume.exe", RESTORE_LOADER},
    {L"Windows\\System32\\wintrust.dll", L"wintrust.dll", RESTORE_CERT},
    {L"Windows\\System32\\crypt32.dll", L"crypt32.dll", RESTORE_CERT},
    {L"Windows\\SysWOW64\\wintrust.dll", L"SysWOW64\\wintrust.dll", RESTORE_CERT},
    {L"Windows\\SysWOW64\\crypt32.dll", L"SysWOW64\\crypt32.dll", RESTORE_CERT},
    {L"EFI\\Microsoft\\Boot\\winload.efi", L"winload.efi", RESTORE_LOADER},
    {L"EFI\\Microsoft\\Boot\\winresume.efi", L"winresume.efi", RESTORE_LOADER},
    {L"bootmgr", L"bootmgr", RESTORE_LOADER},
    {L"Boot\\winload.exe", L"Boot\\winload.exe", RESTORE_LOADER},
    {L"Boot\\winresume.exe", L"Boot\\winresume.exe", RESTORE_LOADER}
};

enum { KNOWN_ORIGINAL_COUNT = sizeof known_originals / sizeof known_originals[0] };

/* A /cishim-restore also has to cover the loaders of the same root, and a
   /wintrust-restore the certificate modules of both architectures. */
static BOOL restore_selected(unsigned set, unsigned wanted)
{
    if (wanted == RESTORE_ALL || set == wanted)
        return TRUE;
    if (wanted == RESTORE_CI && set == RESTORE_LOADER)
        return TRUE;
    return FALSE;
}

static BOOL restore_close(HANDLE file)
{
    return file == INVALID_HANDLE_VALUE || CloseHandle(file);
}

static BOOL restore_one(BCRYPT_ALG_HANDLE algorithm, const PatchScope *scope, const wchar_t *target,
                        RestoreCount *count)
{
    wchar_t backup[PATH_SIZE], final[OFFLINE_NT_PATH];
    if (!ci_find_backup(target, backup))
        return TRUE;
    if (!spp_path_chain(target, FALSE) || GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"A retained original exists without its target: %ls\n", target);
        ++count->failed;
        return FALSE;
    }

    HANDLE source = spp_open(backup, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    if (source == INVALID_HANDLE_VALUE) {
        ci_io_error(L"open the retained original", backup, GetLastError());
        ++count->failed;
        return FALSE;
    }
    Output original = {0};
    Image image;
    if (!offline_read(source, &original, algorithm) ||
        !image_open_arch(&image, original.data, original.size, TRUE)) {
        fwprintf(stderr, L"%ls is not a usable original image. The target was not changed.\n", backup);
        free(original.data);
        CloseHandle(source);
        ++count->failed;
        return FALSE;
    }

    OfflineEdit edit = {0};
    edit.file = spp_open(target, GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
                         OPEN_EXISTING);
    BOOL metadata = edit.file != INVALID_HANDLE_VALUE;
    if (!metadata && GetLastError() == ERROR_ACCESS_DENIED)
        edit.file = spp_open(target, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, OPEN_EXISTING);
    if (edit.file == INVALID_HANDLE_VALUE) {
        ci_io_error(L"open for restore", target, GetLastError());
        free(original.data);
        CloseHandle(source);
        ++count->failed;
        return FALSE;
    }
    wcsncpy(edit.path, target, PATH_SIZE - 1);
    edit.path[PATH_SIZE - 1] = L'\0';

    BOOL ok = GetFileInformationByHandle(edit.file, &edit.id) && offline_path_name(edit.file, final) &&
              offline_under(final, scope->allow_final) && !offline_under(final, scope->live_final);
    if (!ok) {
        fwprintf(stderr, L"Cannot restore into %ls: the path is outside the selected folder or inside running Windows.\n",
                 target);
        free(original.data);
        CloseHandle(source);
        CloseHandle(edit.file);
        ++count->failed;
        return FALSE;
    }

    Output current = {0};
    if (!offline_read(edit.file, &current, algorithm)) {
        fwprintf(stderr, L"Cannot read %ls.\n", target);
        free(current.data);
        free(original.data);
        CloseHandle(source);
        CloseHandle(edit.file);
        ++count->failed;
        return FALSE;
    }
    if (!strcmp(current.sha, original.sha)) {
        wprintf(L"%ls\n  already matches the retained original. The backup is unchanged.\n", target);
        ++count->absent;
        free(current.data);
        free(original.data);
        CloseHandle(source);
        CloseHandle(edit.file);
        return TRUE;
    }

    if (edit.id.dwFileAttributes & FILE_ATTRIBUTE_READONLY) {
        if (!offline_reopen_readonly(edit.file, FALSE)) {
            fwprintf(stderr, L"Cannot clear the read-only attribute on %ls (Win32 %lu).\n", target, GetLastError());
            ok = FALSE;
        }
        edit.restore_readonly = TRUE;
    }
    if (ok) {
        wprintf(L"%ls\n  restoring from %ls\n", target, backup);
        edit.after = original;
        edit.before = current;
        ok = offline_write(&edit, &original, algorithm);
        if (!ok) {
            ci_io_error(L"write and verify", edit.path, GetLastError());
            if (!offline_write(&edit, &current, algorithm))
                fwprintf(stderr, L"Restore rollback failed for %ls.\n", target);
        } else if (metadata) {
            DWORD error = spp_restore_metadata(source, edit.file);
            if (error != ERROR_SUCCESS)
                fwprintf(stderr, L"Contents restored, but the retained permissions could not be applied to %ls (Win32 %lu).\n",
                         target, error);
        } else {
            wprintf(L"  contents restored; the retained permissions need an elevated or SYSTEM prompt.\n");
        }
    }
    if (edit.restore_readonly && !offline_readonly(edit.file, TRUE))
        fwprintf(stderr, L"Could not restore the read-only attribute on %ls.\n", target);

    if (ok) {
        Output verify = {0};
        LARGE_INTEGER start = {0};
        ok = SetFilePointerEx(edit.file, start, NULL, FILE_BEGIN) &&
             offline_read(edit.file, &verify, algorithm) && !strcmp(verify.sha, original.sha);
        free(verify.data);
        if (!ok)
            fwprintf(stderr, L"Verification failed after restoring %ls.\n", target);
        else if (!spp_remove(backup))
            fwprintf(stderr, L"Restored %ls, but the backup %ls remains (Win32 %lu).\n", target, backup, GetLastError());
        else {
            wprintf(L"  verified  SHA-256 %hs  backup removed\n", original.sha);
            ++count->restored;
        }
    }
    restore_close(edit.file);
    restore_close(source);
    free(current.data);
    free(original.data);
    if (!ok)
        ++count->failed;
    return ok;
}

static BOOL patch_restore_command(BCRYPT_ALG_HANDLE algorithm, const wchar_t *argument, unsigned set)
{
    wchar_t path[PATH_SIZE];
    InputKind input;
    if (!normalize(path, argument) || !patch_input_kind(path, &input)) {
        fwprintf(stderr, L"Specify the offline Windows root, the extracted folder, or the file that was patched.\n");
        return FALSE;
    }
    PatchScope scope;
    RestoreCount count = {0};
    BOOL ok = TRUE;

    if (input == INPUT_FILE) {
        wchar_t parent[PATH_SIZE];
        if (!patch_parent_directory(path, parent) || !patch_scope_init(&scope, parent)) {
            fwprintf(stderr, L"Cannot resolve the folder that contains %ls.\n", path);
            return FALSE;
        }
        ok = restore_one(algorithm, &scope, path, &count);
    } else {
        if (!patch_scope_init(&scope, path)) {
            fwprintf(stderr, L"Cannot resolve a safe folder at %ls.\n", path);
            return FALSE;
        }
        for (unsigned i = 0; i < KNOWN_ORIGINAL_COUNT; ++i) {
            if (!restore_selected(known_originals[i].set, set))
                continue;
            const wchar_t *names[2] = {known_originals[i].relative, known_originals[i].leaf};
            for (unsigned j = 0; j < 2; ++j) {
                wchar_t candidate[PATH_SIZE];
                if (!names[j] || !build_path(candidate, path, names[j]))
                    continue;
                if (GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES)
                    continue;
                ok = restore_one(algorithm, &scope, candidate, &count) && ok;
            }
        }
    }

    static const wchar_t *const labels[] = {L"", L"CI and loader ", L"loader ", L"certificate "};
    if (count.restored)
        wprintf(L"%u %lsoriginal file(s) restored in %ls.\n", count.restored, labels[set],
                input == INPUT_FILE ? patch_leaf(path) : path);
    else if (count.absent)
        wprintf(L"No retained original needed restoration.\n");
    else if (count.failed)
        fwprintf(stderr, L"No file was restored. Check the messages above.\n");
    else
        wprintf(L"No retained original (.bak) was found beside the selected files.\n");
    return ok && count.failed == 0 && (count.restored || count.absent);
}

