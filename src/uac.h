/* /uac - keep the elevation prompt working when the AMSI provider is missing.

   consent.exe (System32, 192 KB) is started by AppInfo for every elevation on the
   secure desktop. Its imports show the reason the prompt fails on this build:

     Amsi.dll!AmsiUacInitialize, AmsiUacScan, AmsiUninitialize

   There is no WinVerifyTrust and no catalog API in the binary, so the signature
   work never touched this path. AmsiUacInitialize asks the registered AMSI provider
   (Windows Defender) for a scanner; when WinDefend cannot run, the call fails, the
   function returns early and the elevation request fails, which the caller reports
   as ERROR_ELEVATION_REQUIRED (740) or as a referral (8235). With UAC disabled no
   consent.exe runs and the same programs start, which matches the report.

   The patch makes both AMSI results non-fatal at the two places that test them:

     ff 15 xx xx xx xx   call [AmsiUacInitialize]
     0f 1f 44 00 00      nop
     85 c0               test eax,eax     ->  31 c0   xor eax,eax
     0f 88 xx xx xx xx   js  failure

   The scan result is treated as "no verdict", which is what an absent provider
   means. The prompt itself, the consent decision and the account checks are
   untouched. The binary is signed with the package certificate afterwards, because
   a rewritten system binary needs a signature the loader accepts, and the retained
   original is FILE.bak next to it with its timestamps and permissions.

   consent.exe is located through its Amsi.dll imports, so the patch does not depend
   on a build number or an offset. */

static const wchar_t *const uac_relative = L"Windows\\System32\\consent.exe";

/* Force the AMSI result that is tested right after a call to one of the two AMSI
   entry points to zero. Returns the number of patched places. */
static BOOL uac_patch(Image *image, unsigned *patched)
{
    *patched = 0;
    DWORD slots[3];
    const char *names[3] = {"AmsiUacInitialize", "AmsiUacScan", "AmsiUninitialize"};
    unsigned found = 0;
    for (unsigned i = 0; i < 2; ++i) {
        DWORD slot = pe_import_slot(image, "amsi.dll", names[i]);
        if (slot == NONE) {
            fwprintf(stderr, L"  amsi.dll!%hs is not imported; nothing to patch.\n", names[i]);
            return FALSE;
        }
        slots[found++] = slot;
    }
    for (unsigned i = 0; i < found; ++i) {
        DWORD sites[8];
        unsigned count = pe_call_sites(image, slots[i], sites);
        if (!count) {
            fwprintf(stderr, L"  No call to %hs found.\n", names[i]);
            return FALSE;
        }
        for (unsigned s = 0; s < count; ++s) {
            /* The result is tested within the next 12 bytes: test eax,eax. */
            DWORD start = sites[s] + 6;
            for (DWORD o = start; o + 2 <= start + 12 && o + 2 <= image->size; ++o) {
                if (image->bytes[o] != 0x85 || image->bytes[o + 1] != 0xc0)
                    continue;
                if (!code_span(image, o, 2))
                    return FALSE;
                image->bytes[o] = 0x31;      /* xor eax,eax */
                image->bytes[o + 1] = 0xc0;
                ++*patched;
                break;
            }
        }
    }
    if (!*patched) {
        fwprintf(stderr, L"  The AMSI result is not tested next to the calls; nothing was changed.\n");
        return FALSE;
    }
    return TRUE;
}

/* Keep the vendor file next to it before the bytes change; the restore needs it. */
static BOOL uac_retain(const wchar_t *path)
{
    wchar_t backup[PATH_SIZE];
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
              spp_copy_verified(source, copy) && FlushFileBuffers(copy);
    if (ok && spp_restore_metadata(source, copy) != ERROR_SUCCESS)
        wprintf(L"The retained copy keeps the timestamps only (Win32 %lu).\n", GetLastError());
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

/* True when the two AMSI results are already forced to zero. */
static BOOL uac_patched(BCRYPT_ALG_HANDLE algorithm, const wchar_t *path)
{
    HANDLE file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output content = {0};
    BOOL ok = file != INVALID_HANDLE_VALUE && offline_read(file, &content, algorithm);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    unsigned found = 0;
    Image image;
    if (ok && image_open_arch(&image, content.data, content.size, TRUE)) {
        const char *names[2] = {"AmsiUacInitialize", "AmsiUacScan"};
        for (unsigned i = 0; i < 2; ++i) {
            DWORD slot = pe_import_slot(&image, "amsi.dll", names[i]);
            if (slot == NONE)
                continue;
            DWORD sites[8];
            unsigned count = pe_call_sites(&image, slot, sites);
            for (unsigned s = 0; s < count; ++s) {
                DWORD start = sites[s] + 6;
                for (DWORD o = start; o + 2 <= start + 12 && o + 2 <= image.size; ++o)
                    if (image.bytes[o] == 0x31 && image.bytes[o + 1] == 0xc0) {
                        ++found;
                        break;
                    }
            }
        }
    }
    free(content.data);
    return found >= 2;
}

static BOOL uac_apply(BCRYPT_ALG_HANDLE algorithm, const wchar_t *path)
{
    if (!uac_retain(path))
        return FALSE;
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
    BOOL ok = offline_read(file, &content, algorithm);
    unsigned patched = 0;
    Image image;
    if (ok) {
        /* The vendor signature covers the untouched bytes, so it goes before the
           patch: a stale signature makes the later one fail with a bad digest. */
        ok = image_open_arch(&image, content.data, content.size, TRUE) && uac_patch(&image, &patched) &&
             signer_strip_signature(content.data, &content.size) &&
             fix_checksum(content.data, content.size) &&
             digest(algorithm, content.data, content.size, content.sha);
    }
    if (ok) {
        LARGE_INTEGER start = {0}, end = {.QuadPart = content.size};
        ok = SetFilePointerEx(file, start, NULL, FILE_BEGIN) && write_verified(file, &content, algorithm) &&
             SetFilePointerEx(file, end, NULL, FILE_BEGIN) && SetEndOfFile(file) && FlushFileBuffers(file);
    }
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(content.data);
    if (!ok) {
        if (!patched)
            fwprintf(stderr, L"%ls: no supported AMSI check; the file was left unchanged.\n", path);
        else
            ci_io_error(L"rewrite", path, GetLastError());
        return FALSE;
    }
    patch_keep_times(path, &created, &accessed, &written);
    wprintf(L"%ls: %u AMSI result check(s) made non-fatal.\n", patch_leaf(path), patched);
    return TRUE;
}

/* A file that lost its certificate table (stripped while patching) is not
   recognized by CryptSIPRetrieveSubjectGuid. Append an empty WIN_CERTIFICATE and
   point the security directory at it; CryptSIPPutSignedDataMsg then replaces it. */
static BOOL uac_placeholder(BYTE **data, DWORD *size)
{
    BYTE *bytes = *data;
    if (*size < 0x100 || memcmp(bytes, "MZ", 2))
        return FALSE;
    DWORD pe = u32(bytes + 0x3c);
    if (pe > *size - 0x60 || u32(bytes + pe) != IMAGE_NT_SIGNATURE)
        return FALSE;
    WORD opt = u16(bytes + pe + 20);
    BOOL x64 = u16(bytes + pe + 24) == 0x20b;
    if ((DWORD)pe + 24 + opt > *size)
        return FALSE;
    DWORD directory = pe + 24 + (x64 ? 112u : 96u) + 32u;
    if (directory + 8 > *size)
        return FALSE;
    if (u32(bytes + directory) || u32(bytes + directory + 4))
        return TRUE;   /* already has one */
    BYTE *grown = realloc(*data, *size + 8);
    if (!grown)
        return FALSE;
    *data = grown;
    BYTE *certificate = grown + *size;
    memcpy(certificate, &(DWORD){8}, 4);
    certificate[4] = 0x00; certificate[5] = 0x02;   /* WIN_CERT_REVISION_2_0 */
    certificate[6] = 0x02; certificate[7] = 0x00;   /* WIN_CERT_TYPE_PKCS_SIGNED_DATA */
    DWORD offset = *size;
    memcpy(grown + directory, &offset, 4);
    memcpy(grown + directory + 4, &(DWORD){8}, 4);
    *size += 8;
    return TRUE;
}

/* The patched binary gets the package signature here. The certificate is taken
   from the signer itself: reading it back out of the file is a separate query that
   can fail on a catalog-signed system binary, and its failure must not be reported
   as "cannot sign". */
static BOOL uac_sign(BCRYPT_ALG_HANDLE algorithm, const wchar_t *path, NttpCertificate *certificate)
{
    (void)algorithm;
    NttpSigner signer = {0};
    SipApi sip = {0};
    memset(certificate, 0, sizeof *certificate);
    if (!signer_open(&signer, WINTRUST_SUBJECT) || !signer_sip(&sip)) {
        signer_close(&signer);
        return FALSE;
    }
    BOOL ok = signer_sign(&signer, &sip, path) && signer_verify(path);
    if (ok && signer.cert && signer.cert->cbCertEncoded &&
        signer.cert->cbCertEncoded <= sizeof certificate->der) {
        memcpy(certificate->der, signer.cert->pbCertEncoded, signer.cert->cbCertEncoded);
        certificate->size = signer.cert->cbCertEncoded;
    } else {
        ok = FALSE;
    }
    signer_close(&signer);
    if (!ok) {
        memset(certificate, 0, sizeof *certificate);
        fwprintf(stderr, L"%ls: signing or verifying the signature failed (Win32 %lu).\n", path, GetLastError());
        return FALSE;
    }
    wprintf(L"%ls: signed with the local certificate.\n", patch_leaf(path));
    return TRUE;
}

static BOOL uac_restore(BCRYPT_ALG_HANDLE algorithm, const wchar_t *path)
{
    wchar_t backup[PATH_SIZE];
    if (swprintf(backup, PATH_SIZE, L"%ls.bak", path) < 0 ||
        GetFileAttributesW(backup) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"No retained original at %ls.bak.\n", patch_leaf(path));
        return FALSE;
    }
    HANDLE source = spp_open(backup, GENERIC_READ, OPEN_EXISTING);
    HANDLE target = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    Output content = {0};
    FILETIME created = {0}, accessed = {0}, written = {0};
    if (source != INVALID_HANDLE_VALUE)
        GetFileTime(source, &created, &accessed, &written);
    BOOL ok = source != INVALID_HANDLE_VALUE && target != INVALID_HANDLE_VALUE &&
              offline_read(source, &content, algorithm);
    if (ok) {
        LARGE_INTEGER start = {0}, end = {.QuadPart = content.size};
        ok = SetFilePointerEx(target, start, NULL, FILE_BEGIN) && write_verified(target, &content, algorithm) &&
             SetFilePointerEx(target, end, NULL, FILE_BEGIN) && SetEndOfFile(target) && FlushFileBuffers(target);
    }
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (target != INVALID_HANDLE_VALUE)
        CloseHandle(target);
    free(content.data);
    if (!ok) {
        ci_io_error(L"restore", path, GetLastError());
        return FALSE;
    }
    patch_keep_times(path, &created, &accessed, &written);
    wprintf(L"%ls: original restored.\n", patch_leaf(path));
    return TRUE;
}

/* Resolve consent.exe from a volume root, a folder or the file itself. */
static BOOL uac_resolve(const wchar_t *argument, wchar_t path[PATH_SIZE], wchar_t root[PATH_SIZE],
                        InputKind *input)
{
    PatchScope scope;
    if (!normalize(path, argument) || !patch_input_kind(path, input)) {
        fwprintf(stderr, L"Specify the offline Windows root, a folder, or the file.\n");
        return FALSE;
    }
    root[0] = L'\0';
    if (*input == INPUT_FILE) {
        if (!patch_parent_directory(path, root) || !patch_scope_init(&scope, root))
            return FALSE;
        return TRUE;
    }
    if (!patch_scope_init(&scope, path))
        return FALSE;
    wcsncpy(root, path, PATH_SIZE - 1);
    root[PATH_SIZE - 1] = L'\0';
    wchar_t candidate[PATH_SIZE];
    if (!build_path(candidate, root, *input == INPUT_FLAT ? L"consent.exe" : uac_relative) ||
        GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"consent.exe was not found under %ls.\n", root);
        return FALSE;
    }
    wcscpy(path, candidate);
    return TRUE;
}

/* ---- live mode: rewrite the protected file in place ---- */

/* consent.exe is owned by TrustedInstaller and refuses a write for an administrator.
   The current security descriptor is kept, access is granted for the duration of the
   change, and the descriptor is put back afterwards. */
typedef struct {
    PSECURITY_DESCRIPTOR descriptor;
    SECURITY_INFORMATION information;
    BOOL saved;
} UacGuard;

static BOOL uac_unlock(const wchar_t *path, UacGuard *guard)
{
    memset(guard, 0, sizeof *guard);
    guard->information = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    HANDLE handle = CreateFileW(path, READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle != INVALID_HANDLE_VALUE) {
        guard->saved = GetSecurityInfo(handle, SE_FILE_OBJECT, guard->information, NULL, NULL, NULL, NULL,
                                       &guard->descriptor) == ERROR_SUCCESS;
        CloseHandle(handle);
    }
    HANDLE probe = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    if (probe != INVALID_HANDLE_VALUE) {
        CloseHandle(probe);
        return TRUE;   /* already writable */
    }
    wprintf(L"%ls: taking ownership for the write (Win32 %lu).\n", patch_leaf(path), GetLastError());
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    HANDLE owner = CreateFileW(path, WRITE_OWNER, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (owner != INVALID_HANDLE_VALUE) {
        BYTE administrators[SECURITY_MAX_SID_SIZE];
        DWORD size = sizeof administrators;
        if (CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &size))
            SetSecurityInfo(owner, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, administrators, NULL, NULL, NULL);
        CloseHandle(owner);
    }
    HANDLE dacl = CreateFileW(path, WRITE_DAC, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (dacl != INVALID_HANDLE_VALUE) {
        PACL acl = NULL;
        PSECURITY_DESCRIPTOR permissive = NULL;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;BA)(A;;FA;;;SY)", SDDL_REVISION_1,
                                                                 &permissive, NULL) &&
            GetSecurityDescriptorDacl(permissive, NULL, &acl, NULL)) {
            SetSecurityInfo(dacl, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl, NULL);
        }
        if (permissive)
            LocalFree(permissive);
        CloseHandle(dacl);
    }
    probe = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    if (probe == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"%ls: still not writable (Win32 %lu).\n", path, GetLastError());
        return FALSE;
    }
    CloseHandle(probe);
    return TRUE;
}

static void uac_relock(const wchar_t *path, UacGuard *guard)
{
    if (guard->saved && guard->descriptor)
        SetFileSecurityW(path, guard->information, guard->descriptor);
    if (guard->descriptor)
        LocalFree(guard->descriptor);
    memset(guard, 0, sizeof *guard);
}

/* WinVerifyTrust over the file: this is what the loader will ask, so it is the only
   result that counts. 0 means accepted, CERT_E_UNTRUSTEDROOT means the signature is
   sound but the certificate is not trusted yet. */
static LONG uac_trusted(const wchar_t *path)
{
    HMODULE wintrust = LoadLibraryW(L"wintrust.dll");
    if (!wintrust)
        return -1;
    typedef LONG (WINAPI *VerifyFn)(HWND, GUID *, void *);
    VerifyFn verify = NULL;
    FARPROC address = GetProcAddress(wintrust, "WinVerifyTrust");
    memcpy(&verify, &address, sizeof address);
    LONG status = -1;
    if (verify) {
        WINTRUST_FILE_INFO file = {.cbStruct = sizeof file, .pcwszFilePath = path};
        WINTRUST_DATA data = {.cbStruct = sizeof data, .dwUIChoice = WTD_UI_NONE,
            .dwStateAction = WTD_STATEACTION_VERIFY, .dwUnionChoice = WTD_CHOICE_FILE, .pFile = &file};
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        status = verify(INVALID_HANDLE_VALUE, &action, &data);
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        verify(INVALID_HANDLE_VALUE, &action, &data);
    }
    FreeLibrary(wintrust);
    return status;
}

/* Every step of /uac is written to a small text file, so a failing run can be
   diagnosed without asking for the console again. */
static void uac_report(const wchar_t *path, const wchar_t *result, DWORD error)
{
    wchar_t windows[PATH_SIZE], file[PATH_SIZE];
    if (!GetWindowsDirectoryW(windows, PATH_SIZE) ||
        !build_path(file, windows, L"nttp-uac-report.txt"))
        return;
    HANDLE out = CreateFileW(file, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
        return;
    char buffer[1024];
    int length = 0;
    int written = snprintf(buffer, sizeof buffer,
        "result: %ls\r\nlast error: %lu (0x%08lX)\r\ntarget: %ls\r\n",
        result, error, error, path);
    if (written > 0)
        length = written;
    HANDLE probe = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output content = {0};
    BCRYPT_ALG_HANDLE algorithm;
    if (probe != INVALID_HANDLE_VALUE &&
        BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        offline_read(probe, &content, algorithm)) {
        DWORD pe = u32(content.data + 0x3c);
        BOOL x64 = u16(content.data + pe + 24) == 0x20b;
        DWORD directory = pe + 24 + (x64 ? 112u : 96u) + 32u;
        int more = snprintf(buffer + length, sizeof buffer - length,
            "file size: %lu\r\nsecurity directory: rva 0x%lX size %lu\r\n",
            (unsigned long)content.size, (unsigned long)u32(content.data + directory),
            (unsigned long)u32(content.data + directory + 4));
        if (more > 0 && length + more < (int)sizeof buffer)
            length += more;
    }
    free(content.data);
    if (probe != INVALID_HANDLE_VALUE)
        CloseHandle(probe);
    LONG trust = 1;
    HMODULE wintrust = LoadLibraryW(L"wintrust.dll");
    if (wintrust) {
        typedef LONG (WINAPI *VerifyFn)(HWND, GUID *, void *);
        VerifyFn verify = NULL;
        FARPROC address = GetProcAddress(wintrust, "WinVerifyTrust");
        memcpy(&verify, &address, sizeof address);
        if (verify) {
            WINTRUST_FILE_INFO file_info = {.cbStruct = sizeof file_info, .pcwszFilePath = path};
            WINTRUST_DATA data = {.cbStruct = sizeof data, .dwUIChoice = WTD_UI_NONE,
                .dwStateAction = WTD_STATEACTION_VERIFY, .dwUnionChoice = WTD_CHOICE_FILE,
                .pFile = &file_info};
            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            trust = verify(INVALID_HANDLE_VALUE, &action, &data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            verify(INVALID_HANDLE_VALUE, &action, &data);
        }
        FreeLibrary(wintrust);
    }
    char target_hash[65] = "unreadable";
    HANDLE hash_file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output hash_content = {0};
    BCRYPT_ALG_HANDLE hash_algorithm;
    if (hash_file != INVALID_HANDLE_VALUE &&
        BCryptOpenAlgorithmProvider(&hash_algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
        offline_read(hash_file, &hash_content, hash_algorithm))
        memcpy(target_hash, hash_content.sha, sizeof target_hash);
    free(hash_content.data);
    if (hash_file != INVALID_HANDLE_VALUE)
        CloseHandle(hash_file);
    int more = snprintf(buffer + length, sizeof buffer - length,
        "target sha256: %s\r\nsignature verifies: %s\r\nwinverifytrust: 0x%08lX\r\nembedded signer: %s\r\n",
        target_hash, signer_verify(path) ? "yes" : "no", (unsigned long)trust,
        signer_extract(path, WINTRUST_SUBJECT_NAME, &(NttpCertificate){0}) ? "this package" : "not this package");
    if (more > 0 && length + more < (int)sizeof buffer)
        length += more;
    DWORD count = 0;
    WriteFile(out, buffer, (DWORD)length, &count, NULL);
    CloseHandle(out);
    wprintf(L"Report written to %ls.\n", file);
}

static BOOL uac_live(BCRYPT_ALG_HANDLE algorithm, BOOL restore)
{
    wchar_t windows[PATH_SIZE], path[PATH_SIZE];
    if (!GetWindowsDirectoryW(windows, PATH_SIZE) ||
        !build_path(path, windows, L"System32\\consent.exe"))
        return FALSE;
    enable_privilege(L"SeTakeOwnershipPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeBackupPrivilege");
    BOOL elevated = FALSE;
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof administrators;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &sid_size) ||
        !CheckTokenMembership(NULL, administrators, &elevated) || !elevated) {
        fwprintf(stderr, L"Open an elevated command prompt inside the test Windows.\n");
        return FALSE;
    }
    UacGuard guard;
    if (!uac_unlock(path, &guard))
        return FALSE;
    BOOL ok;
    NttpCertificate certificate = {0};
    if (restore) {
        ok = uac_restore(algorithm, path);
        if (ok) {
            NttpCertificate stale = {0};
            if (signer_extract(path, WINTRUST_SUBJECT_NAME, &stale))
                signer_live_trust(&stale, FALSE);
            wprintf(L"Removed the locally trusted certificate.\n");
        }
    } else {
        BOOL applied = uac_patched(algorithm, path) || uac_apply(algorithm, path);
        ok = applied && uac_sign(algorithm, path, &certificate) && signer_live_trust(&certificate, TRUE);
        if (ok) {
            wprintf(L"The certificate is trusted on this machine.\n");
            LONG status = uac_trusted(path);
            wprintf(L"WinVerifyTrust: 0x%08lX\n", (unsigned long)status);
            if (status == 0 || (unsigned long)status == 0x800B0109UL) {
                wprintf(L"%ls now carries a valid local signature. Start osk.exe, Narrator.exe or\n"
                        L"Magnify.exe to test the prompt.\n", path);
            } else {
                fwprintf(stderr, L"The signature is not accepted (0x%08lX). Restoring the original.\n",
                         (unsigned long)status);
                ok = uac_restore(algorithm, path);
                if (ok)
                    fwprintf(stderr, L"Original restored; the file is back to the vendor version.\n");
            }
        }
    }
    uac_relock(path, &guard);
    uac_report(path, ok ? L"success" : L"failure", GetLastError());
    return ok;
}

static int run_uac(BCRYPT_ALG_HANDLE algorithm, int argc, wchar_t **argv)
{
    BOOL restore = !_wcsicmp(argv[1], L"/uac-restore");
    BOOL approval = !_wcsicmp(argv[1], L"/uac-approval");
    if (argc > 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls [OFFLINE_ROOT|FOLDER|FILE]\n", argv[1]);
        return 2;
    }
    wchar_t given[PATH_SIZE];
    BOOL have_path = argc == 3;
    if (have_path && !normalize(given, argv[2])) {
        fwprintf(stderr, L"Use a local drive path.\n");
        return 2;
    }
    /* Without a path, or for the running installation, the protected file is
       replaced at the next start from a signed copy. Keeping the owner and ACL of
       the retained copy needs these. */
    if (!have_path || wintrust_running(given)) {
        enable_privilege(L"SeBackupPrivilege");
        enable_privilege(L"SeRestorePrivilege");
        enable_privilege(L"SeTakeOwnershipPrivilege");
        BOOL ok = uac_live(algorithm, restore);
        return ok ? 0 : 1;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") ||
        !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    wchar_t path[PATH_SIZE], root[PATH_SIZE];
    InputKind input;
    if (!uac_resolve(argv[2], path, root, &input))
        return 2;
    BOOL ok;
    if (restore) {
        NttpCertificate stale = {0};
        BOOL live = wintrust_running(root) || input == INPUT_FILE;
        if (live)
            signer_extract(path, WINTRUST_SUBJECT_NAME, &stale);
        ok = uac_restore(algorithm, path);
        if (ok && live)
            ok = signer_live_trust(&stale, FALSE);
        else if (ok && input == INPUT_ROOT)
            ok = wintrust_offline_trust(root, NULL, FALSE);
    } else if (approval) {
        /* WinPE: bytes only, no signing provider needed. */
        ok = uac_apply(algorithm, path);
        if (ok)
            wprintf(L"Next run /uac on this volume from a full Windows installation (or on the\n"
                    L"running system) to sign the file and trust the certificate.\n");
    } else {
        /* /uac: patch what is still unpatched, sign, then install the trust. It runs
           on the running system, where a signing provider exists. */
        BOOL applied = uac_patched(algorithm, path) || uac_apply(algorithm, path);
        NttpCertificate certificate = {0};
        ok = applied && uac_sign(algorithm, path, &certificate);
        if (ok) {
            if (wintrust_running(root) || input == INPUT_FILE) {
                ok = signer_live_trust(&certificate, TRUE);
                if (ok)
                    wprintf(L"The certificate is trusted on this machine.\n");
            } else if (input == INPUT_ROOT) {
                ok = wintrust_offline_trust(root, &certificate, TRUE);
            } else {
                wprintf(L"The certificate was not installed: install trust from the offline Windows\n"
                        L"root or on the running system.\n");
            }
        }
    }
    return ok ? 0 : 1;
}
