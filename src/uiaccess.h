/* /uiaccess - let osk.exe, Narrator.exe and Magnify.exe start on a build whose
   Microsoft signature is no longer valid.

   These three programs declare uiAccess="true" in their manifest. The loader only
   grants the uiAccess token to an image signed by a publisher it accepts, and on an
   expired preview build that check fails, so CreateProcess reports
   ERROR_ELEVATION_REQUIRED (740) and the program never starts. A locally trusted
   signature did not satisfy it either, which was measured. Removing the declaration
   drops the requirement: the programs start normally, with the single consequence
   that they can no longer drive windows of elevated processes.

   The attribute is blanked in place with spaces, so the resource keeps its size and
   only the XML text changes:

       <requestedExecutionLevel level="asInvoker" uiAccess="true"/>
       <requestedExecutionLevel level="asInvoker"                />

   The program is then signed with the package certificate, and that certificate is
   trusted in the offline stores, because a rewritten manifest invalidates the
   vendor signature and the loader would otherwise refuse the image. The retained
   original is next to it as FILE.bak, with its timestamps and permissions. */

static const struct {
    const wchar_t *relative;       /* from an offline volume root */
    const wchar_t *live;           /* from %SystemRoot% */
    const wchar_t *leaf;
    const wchar_t *name;
} uiaccess_targets[] = {
    {L"Windows\\System32\\osk.exe", L"System32\\osk.exe", L"osk.exe", L"osk"},
    {L"Windows\\System32\\Narrator.exe", L"System32\\Narrator.exe", L"Narrator.exe", L"Narrator"},
    {L"Windows\\System32\\Magnify.exe", L"System32\\Magnify.exe", L"Magnify.exe", L"Magnify"},
    {L"Windows\\SysWOW64\\osk.exe", L"SysWOW64\\osk.exe", L"osk.exe", L"osk (32-bit)"},
    {L"Windows\\SysWOW64\\Narrator.exe", L"SysWOW64\\Narrator.exe", L"Narrator.exe", L"Narrator (32-bit)"},
    {L"Windows\\SysWOW64\\Magnify.exe", L"SysWOW64\\Magnify.exe", L"Magnify.exe", L"Magnify (32-bit)"}
};

/* Blank the uiAccess declaration, keeping the total length of the manifest. */
static BOOL uiaccess_manifest(BYTE *data, DWORD size)
{
    static const char attribute[] = "uiAccess=\"true\"";
    const unsigned length = sizeof attribute - 1;
    DWORD found = NONE;
    unsigned matches = 0;
    for (DWORD o = 0; o + length <= size; ++o) {
        if (memcmp(data + o, attribute, length))
            continue;
        if (++matches > 1)
            return FALSE;
        found = o;
    }
    if (found == NONE)
        return FALSE;
    DWORD start = found;
    while (start > 0) {
        BYTE previous = data[start - 1];
        if (previous != ' ' && previous != '\t' && previous != '\r' && previous != '\n')
            break;
        --start;
    }
    memset(data + start, ' ', found + length - start);
    return TRUE;
}

static BOOL uiaccess_backup(const wchar_t *path, wchar_t backup[PATH_SIZE])
{
    if (swprintf(backup, PATH_SIZE, L"%ls.bak", path) < 0)
        return FALSE;
    if (GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    HANDLE source = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    HANDLE copy = CreateFileW(backup, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (copy == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
        copy = CreateFileW(backup, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok = source != INVALID_HANDLE_VALUE && copy != INVALID_HANDLE_VALUE &&
              spp_copy_verified(source, copy) && FlushFileBuffers(copy) &&
              spp_restore_metadata(source, copy) == ERROR_SUCCESS;
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (copy != INVALID_HANDLE_VALUE)
        CloseHandle(copy);
    if (!ok) {
        fwprintf(stderr, L"Cannot retain the original at %ls (Win32 %lu). File left unchanged.\n",
                 backup, GetLastError());
        DeleteFileW(backup);
    }
    return ok;
}

static BOOL uiaccess_rewrite(BCRYPT_ALG_HANDLE algorithm, const wchar_t *path)
{
    HANDLE file = spp_open(path, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
        file = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE) {
        ci_io_error(L"open", path, GetLastError());
        return FALSE;
    }
    FILETIME created = {0}, accessed = {0}, written = {0};
    GetFileTime(file, &created, &accessed, &written);
    Output content = {0};
    BOOL ok = offline_read(file, &content, algorithm) && uiaccess_manifest(content.data, content.size) &&
              fix_checksum(content.data, content.size) &&
              signer_strip_signature(content.data, &content.size) &&
              /* the digest that write_verified checks must describe the new bytes */
              digest(algorithm, content.data, content.size, content.sha);
    if (ok) {
        LARGE_INTEGER start = {0}, end = {.QuadPart = content.size};
        ok = SetFilePointerEx(file, start, NULL, FILE_BEGIN) && write_verified(file, &content, algorithm) &&
             SetFilePointerEx(file, end, NULL, FILE_BEGIN) && SetEndOfFile(file) && FlushFileBuffers(file);
    }
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(content.data);
    if (!ok) {
        ci_io_error(L"rewrite", path, GetLastError());
        return FALSE;
    }
    return TRUE;
}

static BOOL uiaccess_sign(BCRYPT_ALG_HANDLE algorithm, NttpSigner *signer, SipApi *sip, const wchar_t *path)
{
    if (!signer_sign(signer, sip, path)) {
        fwprintf(stderr, L"Cannot sign %ls.\n", path);
        return FALSE;
    }
    HANDLE file = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    Output signed_image = {0};
    BOOL ok = file != INVALID_HANDLE_VALUE && offline_read(file, &signed_image, algorithm) &&
              fix_checksum(signed_image.data, signed_image.size);
    if (ok) {
        LARGE_INTEGER start = {0}, end = {.QuadPart = signed_image.size};
        ok = SetFilePointerEx(file, start, NULL, FILE_BEGIN) &&
             write_verified(file, &signed_image, algorithm) &&
             SetFilePointerEx(file, end, NULL, FILE_BEGIN) && SetEndOfFile(file) && FlushFileBuffers(file);
    }
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(signed_image.data);
    return ok;
}

/* ---- live mode: stage signed copies and swap them at the next start ---- */

#define UIACCESS_RECEIPT L"SOFTWARE\\NTTimebombPatch\\UIACCESS"
#define UIACCESS_STAGE L"NTTP-UIACCESS-"

typedef struct {
    DWORD version;
    wchar_t id[33];
    NttpCertificate certificate;
    DWORD count;
    struct {
        wchar_t relative[32];
        char original[65];
        char staged_sha[65];
    } entries[ARRAYSIZE(uiaccess_targets)];
} UiaccessReceipt;

static BOOL uiaccess_dir(const wchar_t *id, wchar_t dir[PATH_SIZE])
{
    wchar_t windows[PATH_SIZE];
    UINT length = GetWindowsDirectoryW(windows, PATH_SIZE);
    return length && length < PATH_SIZE &&
           swprintf(dir, PATH_SIZE, L"%ls\\" UIACCESS_STAGE L"%ls", windows, id) > 0;
}

/* Keep the current file next to the staged one, with owner, ACL and timestamps. */
static BOOL uiaccess_retain(const wchar_t *source, const wchar_t *destination)
{
    HANDLE in = spp_open(source, GENERIC_READ, OPEN_EXISTING);
    HANDLE out = CreateFileW(destination, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, NULL,
                             CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
        out = CreateFileW(destination, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok = in != INVALID_HANDLE_VALUE && out != INVALID_HANDLE_VALUE &&
              spp_copy_verified(in, out) && FlushFileBuffers(out);
    if (ok && spp_restore_metadata(in, out) != ERROR_SUCCESS)
        wprintf(L"The retained copy keeps the timestamps only (Win32 %lu).\n", GetLastError());
    if (in != INVALID_HANDLE_VALUE)
        CloseHandle(in);
    if (out != INVALID_HANDLE_VALUE)
        CloseHandle(out);
    return ok;
}

static BOOL uiaccess_live(BCRYPT_ALG_HANDLE algorithm, BOOL restore)
{
    UiaccessReceipt receipt = {0};
    DWORD size = sizeof receipt;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, UIACCESS_RECEIPT, L"Receipt", RRF_RT_REG_BINARY,
                                  NULL, &receipt, &size);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        return FALSE;
    wchar_t windows[PATH_SIZE], dir[PATH_SIZE], target[PATH_SIZE], staged[PATH_SIZE], original[PATH_SIZE];
    if (!GetWindowsDirectoryW(windows, PATH_SIZE)) {
        fwprintf(stderr, L"Cannot resolve the running Windows directory.\n");
        return FALSE;
    }

    if (restore) {
        if (status == ERROR_FILE_NOT_FOUND) {
            fwprintf(stderr, L"No /uiaccess operation is recorded.\n");
            return FALSE;
        }
        if (size != sizeof receipt || receipt.version != 1 || !uiaccess_dir(receipt.id, dir))
            return FALSE;
        unsigned queued = 0, expected = 0;
        BOOL ok = TRUE;
        for (unsigned i = 0; ok && i < receipt.count && i < ARRAYSIZE(receipt.entries); ++i) {
            if (!build_path(target, windows, receipt.entries[i].relative) ||
                swprintf(original, PATH_SIZE, L"%ls\\%u-original", dir, i) < 0) {
                ok = FALSE;
                break;
            }
            ++expected;
            if (!patch_schedule_replace(original, target)) {
                ok = FALSE;
                break;
            }
            ++queued;
        }
        if (ok && patch_pending_count(dir) < expected) {
            fwprintf(stderr, L"The restore was not queued completely. Nothing else was changed.\n");
            ok = FALSE;
        }
        if (ok) {
            NttpCertificate stale = {0};
            if (signer_extract(target, WINTRUST_SUBJECT_NAME, &stale))
                signer_live_trust(&stale, FALSE);
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, UIACCESS_RECEIPT);
            wprintf(L"%u restore(s) queued. Restart to finish them.\n", queued);
        }
        return ok;
    }

    if (status == ERROR_SUCCESS) {
        fwprintf(stderr, L"A /uiaccess operation is already recorded. Run /uiaccess-restore and\n"
                         L"restart first.\n");
        return FALSE;
    }
    if (!patch_live_guard(L"/uiaccess"))
        return FALSE;
    BOOL elevated = FALSE;
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof administrators;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &sid_size) ||
        !CheckTokenMembership(NULL, administrators, &elevated) || !elevated) {
        fwprintf(stderr, L"Open an elevated command prompt inside the test Windows.\n");
        return FALSE;
    }

    NttpSigner signer = {0};
    SipApi sip = {0};
    if (!signer_open(&signer, WINTRUST_SUBJECT) || !signer_sip(&sip)) {
        signer_close(&signer);
        return FALSE;
    }

    BYTE random[16];
    receipt.version = 1;
    if (BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        signer_close(&signer);
        return FALSE;
    }
    for (unsigned i = 0; i < sizeof random; ++i)
        swprintf(receipt.id + i * 2, 3, L"%02x", random[i]);
    if (!uiaccess_dir(receipt.id, dir)) {
        fwprintf(stderr, L"Cannot resolve the staging folder.\n");
        return FALSE;
    }

    {
        wchar_t pattern[PATH_SIZE];
        if (swprintf(pattern, PATH_SIZE, L"%ls\\" UIACCESS_STAGE L"*", windows) > 0) {
            WIN32_FIND_DATAW entry;
            HANDLE find = FindFirstFileW(pattern, &entry);
            if (find != INVALID_HANDLE_VALUE) {
                do {
                    if (!(entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
                        !wcscmp(entry.cFileName, L".") || !wcscmp(entry.cFileName, L".."))
                        continue;
                    wchar_t leftover[PATH_SIZE], inner[PATH_SIZE];
                    if (!build_path(leftover, windows, entry.cFileName))
                        continue;
                    if (swprintf(inner, PATH_SIZE, L"%ls\\*", leftover) > 0) {
                        WIN32_FIND_DATAW file;
                        HANDLE files = FindFirstFileW(inner, &file);
                        if (files != INVALID_HANDLE_VALUE) {
                            do {
                                if (!wcscmp(file.cFileName, L".") || !wcscmp(file.cFileName, L".."))
                                    continue;
                                wchar_t victim[PATH_SIZE];
                                if (build_path(victim, leftover, file.cFileName))
                                    DeleteFileW(victim);
                            } while (FindNextFileW(files, &file));
                            FindClose(files);
                        }
                    }
                    RemoveDirectoryW(leftover);
                } while (FindNextFileW(find, &entry));
                FindClose(find);
            }
        }
    }
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof attributes, descriptor, FALSE};
    BOOL created = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, NULL) &&
        (CreateDirectoryW(dir, &attributes) || GetLastError() == ERROR_ALREADY_EXISTS);
    if (descriptor)
        LocalFree(descriptor);
    if (!created) {
        fwprintf(stderr, L"Cannot create the staging folder %ls (Win32 %lu).\n", dir, GetLastError());
        signer_close(&signer);
        return FALSE;
    }

    unsigned changed = 0, failed = 0, queued = 0;
    for (unsigned i = 0; i < ARRAYSIZE(uiaccess_targets); ++i) {
        if (!build_path(target, windows, uiaccess_targets[i].live) ||
            GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES)
            continue;
        NttpCertificate existing = {0};
        if (signer_extract(target, WINTRUST_SUBJECT_NAME, &existing)) {
            wprintf(L"%ls: already signed by this package.\n", uiaccess_targets[i].name);
            continue;
        }
        if (swprintf(staged, PATH_SIZE, L"%ls\\%u-staged", dir, i) < 0 ||
            swprintf(original, PATH_SIZE, L"%ls\\%u-original", dir, i) < 0) {
            ++failed;
            break;
        }
        FILETIME created_time = {0}, accessed_time = {0}, written_time = {0};
        HANDLE info = spp_open(target, FILE_READ_ATTRIBUTES, OPEN_EXISTING);
        BOOL have_times = info != INVALID_HANDLE_VALUE &&
                          GetFileTime(info, &created_time, &accessed_time, &written_time);
        if (info != INVALID_HANDLE_VALUE)
            CloseHandle(info);

        HANDLE file = spp_open(target, GENERIC_READ, OPEN_EXISTING);
        Output content = {0};
        BOOL ok = file != INVALID_HANDLE_VALUE && offline_read(file, &content, algorithm) &&
                  uiaccess_manifest(content.data, content.size) &&
                  fix_checksum(content.data, content.size) &&
                  signer_strip_signature(content.data, &content.size) &&
                  digest(algorithm, content.data, content.size, content.sha);
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        if (ok) {
            DeleteFileW(staged);
            DeleteFileW(original);
            uiaccess_retain(target, original);
        }
        HANDLE out = ok ? CreateFileW(staged, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                                      FILE_ATTRIBUTE_NORMAL, NULL) : INVALID_HANDLE_VALUE;
        if (out != INVALID_HANDLE_VALUE) {
            ok = write_verified(out, &content, algorithm);
            CloseHandle(out);
        } else {
            ok = FALSE;
        }
        free(content.data);
        if (!ok) {
            fwprintf(stderr, L"%ls: cannot prepare the replacement (Win32 %lu).\n",
                     uiaccess_targets[i].name, GetLastError());
            ++failed;
            continue;
        }
        if (!signer_sign(&signer, &sip, staged) ||
            !signer_extract(staged, WINTRUST_SUBJECT_NAME, &receipt.certificate)) {
            fwprintf(stderr, L"%ls: cannot sign the replacement.\n", uiaccess_targets[i].name);
            ++failed;
            continue;
        }
        if (have_times)
            patch_keep_times(staged, &created_time, &accessed_time, &written_time);
        if (!patch_schedule_replace(staged, target)) {
            ++failed;
            continue;
        }
        ++queued;
        char sha[65];
        if (sl_stream_sha(algorithm, original, sha)) {
            memcpy(receipt.entries[receipt.count].original, sha, sizeof receipt.entries[0].original - 1);
            wcsncpy(receipt.entries[receipt.count].relative, uiaccess_targets[i].live,
                    ARRAYSIZE(receipt.entries[0].relative) - 1);
            ++receipt.count;
        }
        ++changed;
        wprintf(L"%ls: queued, signed locally.\n", uiaccess_targets[i].name);
    }
    signer_close(&signer);
    if (!changed && !failed) {
        wprintf(L"All three programs already carry this change.\n");
        return TRUE;
    }
    if (!queued)
        return FALSE;
    if (patch_pending_count(dir) < queued) {
        fwprintf(stderr, L"The pending-rename list does not hold every replacement. Nothing else\n"
                         L"was changed; run /uiaccess-restore and reboot, then retry.\n");
        return FALSE;
    }
    if (!signer_live_trust(&receipt.certificate, TRUE)) {
        fwprintf(stderr, L"The replacements are queued but the certificate could not be trusted.\n");
        return FALSE;
    }
    HKEY key = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, UIACCESS_RECEIPT, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) ||
        RegSetValueExW(key, L"Receipt", 0, REG_BINARY, (const BYTE *)&receipt, sizeof receipt) ||
        RegFlushKey(key)) {
        fwprintf(stderr, L"Cannot store the /uiaccess journal (Win32 %lu).\n", GetLastError());
        if (key)
            RegCloseKey(key);
        return FALSE;
    }
    if (key)
        RegCloseKey(key);
    wprintf(L"%u program(s) staged and signed. Restart to finish the replacement; the originals are\n"
            L"retained under %ls.\n", changed, dir);
    return failed == 0;
}

static BOOL uiaccess_offline(BCRYPT_ALG_HANDLE algorithm, const wchar_t *argument, BOOL restore)
{
    wchar_t path[PATH_SIZE], base[PATH_SIZE];
    InputKind input;
    PatchScope scope;
    if (!normalize(path, argument) || !patch_input_kind(path, &input)) {
        fwprintf(stderr, L"Specify the offline Windows root, the extracted folder, or one file.\n");
        return FALSE;
    }
    if (wintrust_running(path)) {
        fwprintf(stderr, L"%ls is the running installation. Run /uiaccess from WinPE or another\n"
                         L"Windows installation against that volume; these programs are in use here.\n", path);
        return FALSE;
    }
    base[0] = L'\0';
    if (input == INPUT_FILE) {
        if (!patch_parent_directory(path, base) || !patch_scope_init(&scope, base))
            return FALSE;
    } else {
        if (!patch_scope_init(&scope, path))
            return FALSE;
        wcsncpy(base, path, PATH_SIZE - 1);
        base[PATH_SIZE - 1] = L'\0';
    }

    wchar_t candidates[ARRAYSIZE(uiaccess_targets)][PATH_SIZE];
    const wchar_t *names[ARRAYSIZE(uiaccess_targets)];
    unsigned count = 0;
    BOOL flat = input == INPUT_FLAT;
    if (input == INPUT_FILE) {
        wcscpy(candidates[0], path);
        names[0] = patch_leaf(path);
        count = 1;
    } else {
        for (unsigned i = 0; i < ARRAYSIZE(uiaccess_targets); ++i) {
            if (flat && i >= 3)
                break;
            const wchar_t *relative = flat ? uiaccess_targets[i].leaf : uiaccess_targets[i].relative;
            if (!build_path(candidates[count], base, relative) ||
                GetFileAttributesW(candidates[count]) == INVALID_FILE_ATTRIBUTES)
                continue;
            names[count] = uiaccess_targets[i].name;
            ++count;
        }
    }
    if (!count) {
        fwprintf(stderr, L"None of osk.exe, Narrator.exe or Magnify.exe was found under %ls.\n", base);
        return FALSE;
    }

    if (restore) {
        unsigned restored = 0, failed = 0;
        for (unsigned i = 0; i < count; ++i) {
            wchar_t backup[PATH_SIZE];
            if (swprintf(backup, PATH_SIZE, L"%ls.bak", candidates[i]) < 0 ||
                GetFileAttributesW(backup) == INVALID_FILE_ATTRIBUTES) {
                wprintf(L"%ls: no retained original.\n", names[i]);
                ++failed;
                continue;
            }
            HANDLE source = spp_open(backup, GENERIC_READ, OPEN_EXISTING);
            HANDLE target = spp_open(candidates[i], GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
            Output content = {0};
            FILETIME created = {0}, accessed = {0}, written = {0};
            if (source != INVALID_HANDLE_VALUE)
                GetFileTime(source, &created, &accessed, &written);
            BOOL ok = source != INVALID_HANDLE_VALUE && target != INVALID_HANDLE_VALUE &&
                      offline_read(source, &content, algorithm);
            if (ok) {
                LARGE_INTEGER start = {0}, end = {.QuadPart = content.size};
                ok = SetFilePointerEx(target, start, NULL, FILE_BEGIN) &&
                     write_verified(target, &content, algorithm) &&
                     SetFilePointerEx(target, end, NULL, FILE_BEGIN) && SetEndOfFile(target) &&
                     FlushFileBuffers(target);
            }
            if (source != INVALID_HANDLE_VALUE)
                CloseHandle(source);
            if (target != INVALID_HANDLE_VALUE)
                CloseHandle(target);
            free(content.data);
            if (ok) {
                patch_keep_times(candidates[i], &created, &accessed, &written);
                wprintf(L"%ls: original restored.\n", names[i]);
                ++restored;
            } else {
                fwprintf(stderr, L"%ls: restore failed (Win32 %lu).\n", names[i], GetLastError());
                ++failed;
            }
        }
        if (input == INPUT_ROOT) {
            NttpCertificate certificate = {0};
            if (!wintrust_offline_trust(base, &certificate, FALSE))
                ++failed;
        }
        wprintf(L"%u program(s) restored, %u failed, in %ls.\n", restored, failed,
                input == INPUT_FILE ? patch_leaf(path) : base);
        return failed == 0;
    }

    NttpSigner signer = {0};
    SipApi sip = {0};
    NttpCertificate certificate = {0};
    BOOL signed_something = FALSE;
    if (!signer_open(&signer, WINTRUST_SUBJECT) || !signer_sip(&sip)) {
        signer_close(&signer);
        return FALSE;
    }
    unsigned changed = 0, failed = 0;
    for (unsigned i = 0; i < count; ++i) {
        if (signer_extract(candidates[i], WINTRUST_SUBJECT_NAME, &certificate)) {
            wprintf(L"%ls: already signed by this package.\n", names[i]);
            signed_something = TRUE;
            continue;
        }
        wchar_t backup[PATH_SIZE];
        FILETIME created = {0}, accessed = {0}, written = {0};
        HANDLE info = spp_open(candidates[i], FILE_READ_ATTRIBUTES, OPEN_EXISTING);
        BOOL have_times = info != INVALID_HANDLE_VALUE &&
                          GetFileTime(info, &created, &accessed, &written);
        if (info != INVALID_HANDLE_VALUE)
            CloseHandle(info);
        if (!uiaccess_backup(candidates[i], backup) || !uiaccess_rewrite(algorithm, candidates[i]) ||
            !uiaccess_sign(algorithm, &signer, &sip, candidates[i])) {
            ++failed;
            continue;
        }
        if (have_times)
            patch_keep_times(candidates[i], &created, &accessed, &written);
        if (!signer_extract(candidates[i], WINTRUST_SUBJECT_NAME, &certificate)) {
            ++failed;
            continue;
        }
        wprintf(L"%ls: uiAccess requirement removed and signed locally.\n", names[i]);
        signed_something = TRUE;
        ++changed;
    }
    signer_close(&signer);
    if (signed_something) {
        if (input == INPUT_ROOT) {
            if (!wintrust_offline_trust(base, &certificate, TRUE))
                ++failed;
        } else {
            wprintf(L"The offline SOFTWARE hive was not touched: install trust from the offline\n"
                    L"Windows root, not from a flat folder or a single file.\n");
        }
    }
    if (!changed && !failed)
        wprintf(L"All %u program(s) already carry this change.\n", count);
    if (changed)
        wprintf(L"%u program(s) changed. They start without the uiAccess publisher check and can no\n"
                L"longer drive windows of elevated processes.\n", changed);
    return failed == 0;
}

static int run_uiaccess(BCRYPT_ALG_HANDLE algorithm, int argc, wchar_t **argv)
{
    BOOL restore = !_wcsicmp(argv[1], L"/uiaccess-restore");
    if (argc > 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls [OFFLINE_ROOT|FOLDER|FILE]\n", argv[1]);
        return 2;
    }
    wchar_t path[PATH_SIZE];
    BOOL have_path = argc == 3;
    if (have_path && !normalize(path, argv[2])) {
        fwprintf(stderr, L"Use a local drive path.\n");
        return 2;
    }
    /* Without a path, or for the running installation, the programs are in use and
       the signed replacements are staged for the next start. */
    if (!have_path || wintrust_running(path)) {
        BOOL ok = uiaccess_live(algorithm, restore);
        return ok ? 0 : 1;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") ||
        !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BOOL ok = uiaccess_offline(algorithm, path, restore);
    return ok ? 0 : 1;
}
