static DWORD mmc_approval_data(const Image *im, DWORD rva, DWORD length)
{
    DWORD raw = translate(im, rva, FALSE, FALSE);
    if (!length || raw == NONE || length > im->size - raw || length - 1 > UINT32_MAX - rva ||
        translate(im, rva, FALSE, TRUE) != NONE ||
        translate(im, rva + length - 1, FALSE, FALSE) != raw + length - 1) return NONE;
    return raw;
}

static BOOL mmc_approval_name(const Image *im, DWORD slot, unsigned width, uint64_t base, const wchar_t *name)
{
    uint64_t address = 0;
    memcpy(&address, im->bytes + slot, width);
    if (address < base || address - base >= NONE) return FALSE;
    size_t length = wcslen(name);
    DWORD raw = mmc_approval_data(im, (DWORD)(address - base), (DWORD)((length + 1) * sizeof *name));
    return raw != NONE && !(raw & 1) && !u16(im->bytes + raw + length * sizeof *name) &&
           !_wcsnicmp((const wchar_t *)(im->bytes + raw), name, length);
}

static BOOL mmc_approval_relocations(const Image *im, DWORD table, unsigned width, unsigned count)
{
    DWORD directory = im->pe + 24 + (im->x64 ? 112 : 96) + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
    if (directory + 8 > im->section_table ||
        u32(im->bytes + im->pe + 24 + (im->x64 ? 108 : 92)) <= IMAGE_DIRECTORY_ENTRY_BASERELOC) return FALSE;
    DWORD size = u32(im->bytes + directory + 4);
    DWORD raw = mmc_approval_data(im, u32(im->bytes + directory), size);
    if (raw == NONE) return FALSE;
    DWORD expected_type = im->x64 ? IMAGE_REL_BASED_DIR64 : IMAGE_REL_BASED_HIGHLOW;
    unsigned found = 0;
    for (DWORD offset = 0; offset < size;) {
        const BYTE *block = im->bytes + raw + offset;
        if (size - offset < 8) return FALSE;
        DWORD page = u32(block), length = u32(block + 4);
        if ((page & 0xfff) || length < 8 || (length & 3) || length > size - offset) return FALSE;
        for (DWORD i = 8; i < length; i += 2) {
            WORD entry = u16(block + i);
            DWORD rva = page + (entry & 0xfff), type = entry >> 12;
            if (!type || rva < table || rva - table >= width * count) continue;
            if (type != expected_type || (rva - table) % width) return FALSE;
            unsigned bit = 1u << ((rva - table) / width);
            if (found & bit) return FALSE;
            found |= bit;
        }
        offset += length;
    }
    return found == (1u << count) - 1;
}

static BOOL mmc_approval_patch(Output *output)
{
    static const wchar_t *const names[] = {
        L"cttunesvr.exe", L"inetmgr.exe", L"migsetup.exe", L"mmc.exe", L"oobe.exe",
        L"pkgmgr.exe", L"provisionshare.exe", L"provisionstorage.exe", L"spinstall.exe", L"winsat.exe"
    };
    Image im;
    if (!image_open_arch(&im, output->data, output->size, TRUE) ||
        !(u16(im.bytes + im.pe + 22) & IMAGE_FILE_DLL) ||
        (u16(im.bytes + im.pe + 24 + 70) & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)) return FALSE;
    unsigned width = im.x64 ? 8 : 4;
    uint64_t base = 0;
    memcpy(&base, im.bytes + im.pe + 24 + (im.x64 ? 24 : 28), width);

    DWORD slot = NONE, table_offset = NONE;
    for (unsigned i = 0; i < im.sections; ++i) {
        const BYTE *section = im.bytes + im.section_table + i * 40;
        DWORD flags = u32(section + 36), rva = u32(section + 12);
        if (!(flags & IMAGE_SCN_CNT_INITIALIZED_DATA) || !(flags & IMAGE_SCN_MEM_READ) ||
            (flags & IMAGE_SCN_MEM_EXECUTE) || rva % width) continue;
        DWORD raw = u32(section + 20), length = u32(section + 16);
        unsigned minimum = (unsigned)ARRAYSIZE(names) * width;
        for (DWORD offset = 0; length - offset >= minimum; offset += width) {
            DWORD start = raw + offset;
            if (!mmc_approval_name(&im, start, width, base, names[0])) continue;
            unsigned extra = length - offset >= minimum + width &&
                mmc_approval_name(&im, start + 3 * width, width, base, L"migwiz.exe");
            unsigned n = 1;
            while (n < ARRAYSIZE(names) &&
                   mmc_approval_name(&im, start + (n + (n >= 3 ? extra : 0)) * width, width, base, names[n]))
                ++n;
            if (n != ARRAYSIZE(names) ||
                !mmc_approval_relocations(&im, rva + offset, width, n + extra)) continue;
            if (slot != NONE) return FALSE;
            slot = start + (3 + extra) * width;
            table_offset = start;
        }
    }
    if (slot == NONE) return FALSE;
    /* Duplicate the previous sorted entry. This preserves the table length and
       every other executable's lookup result, including in the MigWiz layout. */
    memcpy(im.bytes + slot, im.bytes + slot - width, width);

    return fix_checksum(im.bytes, im.size);
}

static BOOL mmc_approval_stage(const wchar_t *path, HANDLE original, const Output *content,
                               DWORD attributes, BCRYPT_ALG_HANDLE algorithm)
{
    HANDLE file = spp_open(path, GENERIC_WRITE | WRITE_OWNER | WRITE_DAC, CREATE_NEW);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    DWORD size = 0;
    BOOL ok = WriteFile(file, content->data, content->size, &size, NULL) && size == content->size &&
              FlushFileBuffers(file) && spp_restore_metadata(original, file) == ERROR_SUCCESS;
    CloseHandle(file);
    char sha[65];
    ok = ok && sl_attribute(path, attributes) && sl_stream_sha(algorithm, path, sha) && !strcmp(sha, content->sha);
    if (!ok) spp_remove(path);
    return ok;
}

static BOOL mmc_approval_edit(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root, BOOL restore)
{
    wchar_t target[PATH_SIZE], backup[PATH_SIZE], stage[PATH_SIZE], lock_path[PATH_SIZE];
    if (!offline_root(root, FALSE) ||
        !sl_target_file(root, L"Windows\\System32\\appinfo.dll", target) ||
        swprintf(backup, PATH_SIZE, L"%ls.nttp-mmc-original", target) < 0 ||
        swprintf(stage, PATH_SIZE, L"%ls.nttp-mmc-%lu", target, GetCurrentProcessId()) < 0 ||
        swprintf(lock_path, PATH_SIZE, L"%ls.nttp-mmc.lock", target) < 0 ||
        !spp_path_type(backup, FALSE, TRUE)) return FALSE;

    HANDLE lock = CreateFileW(lock_path, DELETE | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (lock == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot acquire the MMC approval lock (Win32 %lu).\n", GetLastError());
        return FALSE;
    }
    HANDLE file = spp_open(target, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    HANDLE saved = INVALID_HANDLE_VALUE;
    Output current = {0}, original = {0}, patched = {0}, signed_replacement = {0};
    NttpSigner appinfo_signer = {0};
    SipApi appinfo_sip = {0};
    NttpCertificate appinfo_certificate = {0};
    char signed_sha[65];
    BOOL ok = FALSE, staged = FALSE, signed_by_package = FALSE;
    BY_HANDLE_FILE_INFORMATION attributes;
    if (file == INVALID_HANDLE_VALUE || !offline_read(file, &current, algorithm)) goto done;
    saved = spp_open(backup, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    BOOL has_backup = saved != INVALID_HANDLE_VALUE;
    if (has_backup ? !offline_read(saved, &original, algorithm) : !spp_missing(GetLastError())) goto done;
    const Output *base = has_backup ? &original : &current;
    patched.size = base->size;
    patched.data = malloc(patched.size);
    if (!patched.data) goto done;
    memcpy(patched.data, base->data, patched.size);
    if (!mmc_approval_patch(&patched) || !digest(algorithm, patched.data, patched.size, patched.sha)) {
        fwprintf(stderr, L"Cannot identify one supported MMC automatic-approval table in %ls. No replacement made.\n",
                 has_backup ? backup : target);
        goto done;
    }
    BOOL installed = !strcmp(current.sha, patched.sha);
    if (!installed && strcmp(current.sha, base->sha)) {
        fwprintf(stderr, L"Current AppInfo differs from the backup and its expected patch. No replacement made.\n");
        goto done;
    }
    if (restore && !installed) {
        wprintf(L"Original AppInfo is already in place.\n");
        ok = TRUE;
        goto done;
    }
    if (!restore && installed) {
        wprintf(L"MMC approval change is already in place. Original retained at %ls.\n", backup);
        ok = TRUE;
        goto done;
    }
    if (!has_backup) {
        /* Keep the original NTFS file object so restore can recover all of its metadata. */
        if (!CreateHardLinkW(backup, target, NULL)) {
            ci_io_error(L"retain an NTFS hard-link backup at", backup, GetLastError());
            goto done;
        }
        saved = spp_open(backup, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    }
    char sha[65];
    if (saved == INVALID_HANDLE_VALUE || !sl_stream_sha(algorithm, backup, sha) ||
        strcmp(sha, base->sha) || !GetFileInformationByHandle(saved, &attributes)) {
        fwprintf(stderr, L"Original AppInfo backup is missing or has changed.\n");
        goto done;
    }
    const Output *replacement = restore ? base : &patched;
    if (restore) {
        if (!CreateHardLinkW(stage, backup, NULL)) {
            ci_io_error(L"stage original AppInfo at", stage, GetLastError());
            goto done;
        }
    } else if (!mmc_approval_stage(stage, saved, replacement, attributes.dwFileAttributes, algorithm)) {
        goto done;
    }
    staged = TRUE;
    /* Signing is optional. WinPE has no signing provider, and there the file is
       loaded with the CI patch and nointegritychecks, which do not require a valid
       signature. When a provider exists the file is signed and the certificate is
       trusted, which also works on a machine with the default CI policy. */
    if (!restore) {
        BOOL can_sign = signer_open(&appinfo_signer, WINTRUST_SUBJECT) && signer_sip(&appinfo_sip);
        if (can_sign)
            can_sign = signer_sign(&appinfo_signer, &appinfo_sip, stage) &&
                       signer_extract(stage, WINTRUST_SUBJECT_NAME, &appinfo_certificate);
        if (!can_sign) {
            wprintf(L"No signing provider here: the patch is written without a local signature.\n"
                    L"The file only loads when the CI patch and nointegritychecks are in place.\n");
            signer_close(&appinfo_signer);
            memset(&appinfo_certificate, 0, sizeof appinfo_certificate);
            signed_by_package = FALSE;
        } else {
            signed_by_package = TRUE;
            if (!sl_stream_sha(algorithm, stage, signed_sha)) {
                fwprintf(stderr, L"Cannot read back the signed AppInfo.\n");
                goto done;
            }
            replacement = &signed_replacement;
            signed_replacement.size = patched.size;
            signed_replacement.data = patched.data;
            memcpy(signed_replacement.sha, signed_sha, sizeof signed_replacement.sha);
        }
    }
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    CloseHandle(saved);
    saved = INVALID_HANDLE_VALUE;
    if (!sl_stream_sha(algorithm, target, sha) || strcmp(sha, current.sha)) {
        fwprintf(stderr, L"AppInfo changed while preparing the replacement.\n");
        goto done;
    }
    if (!MoveFileExW(stage, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ci_io_error(L"replace offline", target, GetLastError());
        goto done;
    }
    staged = FALSE;
    ok = sl_stream_sha(algorithm, target, sha) && !strcmp(sha, replacement->sha);
    if (ok && !restore && signed_by_package)
        ok = wintrust_offline_trust(root, &appinfo_certificate, TRUE);
    if (ok && restore) {
        NttpCertificate stale = {0};
        if (signer_extract(target, WINTRUST_SUBJECT_NAME, &stale))
            ok = wintrust_offline_trust(root, &stale, FALSE);
    }
    if (ok) {
        if (restore) wprintf(L"Restored original AppInfo and permissions.\n");
        else wprintf(L"Removed MMC from AppInfo automatic elevation and signed AppInfo locally.\n"
                     L"Original retained at %ls.\n", backup);
    }
done:
    if (!ok) fwprintf(stderr, L"AppInfo operation failed. Preserve any original backup at %ls.\n", backup);
    if (staged && !(restore ? DeleteFileW(stage) : spp_remove(stage)))
        fwprintf(stderr, L"Staged file retained at %ls.\n", stage);
    if (saved != INVALID_HANDLE_VALUE) CloseHandle(saved);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    signer_close(&appinfo_signer);
    free(current.data);
    free(original.data);
    free(patched.data);
    CloseHandle(lock);
    return ok;
}

/* ---- live mode: stage the replacement and swap it at the next start ---- */

#define MMC_APPROVAL_RECEIPT L"SOFTWARE\\NTTimebombPatch\\MMCApproval"
#define MMC_APPROVAL_STAGE L"NTTP-MMCAPPROVAL-"

typedef struct {
    DWORD version;
    wchar_t id[33];
    char original[65];
    char patched[65];
} MmcApprovalReceipt;

static BOOL mmc_approval_dir(const wchar_t *id, wchar_t dir[PATH_SIZE])
{
    wchar_t windows[PATH_SIZE];
    UINT length = GetWindowsDirectoryW(windows, PATH_SIZE);
    return length && length < PATH_SIZE &&
           swprintf(dir, PATH_SIZE, L"%ls\\" MMC_APPROVAL_STAGE L"%ls", windows, id) > 0;
}

static BOOL mmc_approval_live(BCRYPT_ALG_HANDLE algorithm, BOOL restore)
{
    MmcApprovalReceipt receipt = {0};
    DWORD size = sizeof receipt;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, MMC_APPROVAL_RECEIPT, L"Receipt", RRF_RT_REG_BINARY,
                                  NULL, &receipt, &size);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        return FALSE;
    wchar_t windows[PATH_SIZE], target[PATH_SIZE], dir[PATH_SIZE], staged[PATH_SIZE], original[PATH_SIZE];
    if (!GetWindowsDirectoryW(windows, PATH_SIZE) ||
        !build_path(target, windows, L"System32\\appinfo.dll"))
        return FALSE;

    if (restore) {
        if (status == ERROR_FILE_NOT_FOUND) {
            fwprintf(stderr, L"No /mmc-approval operation is recorded.\n");
            return FALSE;
        }
        if (size != sizeof receipt || receipt.version != 1 || receipt.id[32] ||
            !mmc_approval_dir(receipt.id, dir) ||
            swprintf(original, PATH_SIZE, L"%ls\\appinfo.dll.original", dir) < 0)
            return FALSE;
        if (!patch_schedule_replace(original, target) || patch_pending_count(dir) < 1) {
            fwprintf(stderr, L"The restore was not queued. Nothing was changed.\n");
            return FALSE;
        }
        NttpCertificate stale = {0};
        if (signer_extract(target, WINTRUST_SUBJECT_NAME, &stale))
            signer_live_trust(&stale, FALSE);
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, MMC_APPROVAL_RECEIPT);
        wprintf(L"Restore of %ls is queued. Restart to finish it.\n", target);
        return TRUE;
    }
    if (status == ERROR_SUCCESS) {
        fwprintf(stderr, L"A /mmc-approval operation is already recorded. Run /mmc-approval-restore and restart.\n");
        return FALSE;
    }
    BOOL elevated = FALSE;
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof administrators;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &sid_size) ||
        !CheckTokenMembership(NULL, administrators, &elevated) || !elevated) {
        fwprintf(stderr, L"Open an elevated command prompt inside the test Windows.\n");
        return FALSE;
    }
    if (!patch_live_guard(L"/mmc-approval"))
        return FALSE;
    /* Keeping the owner and ACL of the retained copy needs these. */
    enable_privilege(L"SeBackupPrivilege");
    enable_privilege(L"SeRestorePrivilege");
    enable_privilege(L"SeTakeOwnershipPrivilege");

    HANDLE file = spp_open(target, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    Output current = {0}, patched = {0};
    BOOL ok = file != INVALID_HANDLE_VALUE && offline_read(file, &current, algorithm);
    FILETIME created = {0}, accessed = {0}, written = {0};
    if (ok)
        GetFileTime(file, &created, &accessed, &written);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok) {
        free(current.data);
        return FALSE;
    }
    patched.size = current.size;
    patched.data = malloc(patched.size);
    ok = patched.data != NULL;
    if (ok) {
        memcpy(patched.data, current.data, patched.size);
        ok = mmc_approval_patch(&patched) && digest(algorithm, patched.data, patched.size, patched.sha);
    }
    if (!ok) {
        fwprintf(stderr, L"Cannot identify one supported MMC automatic-approval table in %ls. Nothing changed.\n",
                 target);
        free(current.data);
        free(patched.data);
        return FALSE;
    }
    if (!strcmp(current.sha, patched.sha)) {
        wprintf(L"%ls already carries the MMC automatic-approval entry.\n", target);
        free(current.data);
        free(patched.data);
        return TRUE;
    }

    BYTE random[16];
    receipt.version = 1;
    if (BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0 ||
        !mmc_approval_dir(receipt.id, dir)) {
        free(current.data);
        free(patched.data);
        return FALSE;
    }
    for (unsigned i = 0; i < sizeof random; ++i)
        swprintf(receipt.id + i * 2, 3, L"%02x", random[i]);
    memcpy(receipt.original, current.sha, sizeof receipt.original - 1);
    memcpy(receipt.patched, patched.sha, sizeof receipt.patched - 1);

    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof attributes, descriptor, FALSE};
    BOOL created_dir = ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, NULL) &&
        (CreateDirectoryW(dir, &attributes) || GetLastError() == ERROR_ALREADY_EXISTS);
    if (descriptor)
        LocalFree(descriptor);
    if (created_dir &&
        (swprintf(staged, PATH_SIZE, L"%ls\\appinfo.dll", dir) < 0 ||
         swprintf(original, PATH_SIZE, L"%ls\\appinfo.dll.original", dir) < 0))
        created_dir = FALSE;
    if (!created_dir) {
        fwprintf(stderr, L"Cannot prepare the staging folder %ls (Win32 %lu).\n", dir, GetLastError());
        free(current.data);
        free(patched.data);
        return FALSE;
    }

    HANDLE out = CreateFileW(staged, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                             FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written_count = 0;
    ok = out != INVALID_HANDLE_VALUE &&
         WriteFile(out, patched.data, patched.size, &written_count, NULL) &&
         written_count == patched.size && FlushFileBuffers(out);
    if (out != INVALID_HANDLE_VALUE)
        CloseHandle(out);
    free(patched.data);
    if (!ok) {
        fwprintf(stderr, L"Cannot write %ls.\n", staged);
        free(current.data);
        return FALSE;
    }
    /* The patched AppInfo needs a signature the loader accepts, and that
       certificate must be trusted on this machine. */
    NttpSigner appinfo = {0};
    SipApi appinfo_sip = {0};
    NttpCertificate appinfo_certificate = {0};
    BOOL signed_ok = signer_open(&appinfo, WINTRUST_SUBJECT) && signer_sip(&appinfo_sip) &&
                     signer_sign(&appinfo, &appinfo_sip, staged) &&
                     signer_extract(staged, WINTRUST_SUBJECT_NAME, &appinfo_certificate);
    signer_close(&appinfo);
    if (!signed_ok) {
        fwprintf(stderr, L"Cannot sign the staged AppInfo. The target was not changed.\n");
        free(current.data);
        return FALSE;
    }
    patch_keep_times(staged, &created, &accessed, &written);
    /* Keep the current file, with its metadata, for the restore. */
    HANDLE source = spp_open(target, GENERIC_READ, OPEN_EXISTING);
    HANDLE copy = CreateFileW(original, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    ok = source != INVALID_HANDLE_VALUE && copy != INVALID_HANDLE_VALUE &&
         spp_copy_verified(source, copy) && FlushFileBuffers(copy);
    if (ok && spp_restore_metadata(source, copy) != ERROR_SUCCESS)
        wprintf(L"The retained copy keeps the current timestamps only (Win32 %lu).\n", GetLastError());
    if (ok)
        patch_keep_times(original, &created, &accessed, &written);
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (copy != INVALID_HANDLE_VALUE)
        CloseHandle(copy);
    free(current.data);
    if (!ok) {
        fwprintf(stderr, L"Cannot retain the current %ls (Win32 %lu). The target was not changed.\n",
                 target, GetLastError());
        return FALSE;
    }
    if (!patch_schedule_replace(staged, target) || patch_pending_count(dir) < 1) {
        fwprintf(stderr, L"The replacement was not queued. Nothing was changed.\n");
        return FALSE;
    }
    HKEY key = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, MMC_APPROVAL_RECEIPT, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) ||
        RegSetValueExW(key, L"Receipt", 0, REG_BINARY, (const BYTE *)&receipt, sizeof receipt) ||
        RegFlushKey(key)) {
        fwprintf(stderr, L"Cannot store the /mmc-approval journal (Win32 %lu).\n", GetLastError());
        if (key)
            RegCloseKey(key);
        return FALSE;
    }
    if (key)
        RegCloseKey(key);
    if (!signer_live_trust(&appinfo_certificate, TRUE)) {
        fwprintf(stderr, L"The replacement is queued but its certificate could not be trusted.\n");
        return FALSE;
    }
    wprintf(L"Replacement of %ls is queued, signed locally, and the original is retained at %ls.\n"
            L"Restart to finish it.\n", target, original);
    return TRUE;
}

static BOOL mmc_approval_running(const wchar_t *path)
{
    wchar_t live[PATH_SIZE], live_final[OFFLINE_NT_PATH], candidate[OFFLINE_NT_PATH];
    UINT length = GetSystemWindowsDirectoryW(live, PATH_SIZE);
    if (!length || length >= PATH_SIZE || !offline_directory(path, candidate) ||
        !offline_directory(live, live_final))
        return FALSE;
    return !_wcsicmp(candidate, live_final) || offline_under(candidate, live_final) ||
           offline_under(live_final, candidate);
}

static int run_mmc_approval(int argc, wchar_t **argv)
{
    fwprintf(stderr, L"Note: /mmc-approval is deprecated. The programs it targeted start with\n"
                     L"EnableLUA=0, which is the documented workaround now.\n");
    BOOL restore = !_wcsicmp(argv[1], L"/mmc-approval-restore");
    if (argc > 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls [OFFLINE_WINDOWS_ROOT]\n", argv[1]);
        return 2;
    }
    wchar_t root[PATH_SIZE];
    BOOL have_root = argc == 3;
    if (have_root && !normalize(root, argv[2])) {
        fwprintf(stderr, L"Use a local drive path.\n");
        return 2;
    }
    /* Without a path, or with the running installation, the file is in use and
       the replacement is staged for the next start. */
    BOOL live = !have_root || mmc_approval_running(root);
    if (live) {
        BCRYPT_ALG_HANDLE algorithm;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) return 1;
        BOOL ok = mmc_approval_live(algorithm, restore);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return ok ? 0 : 1;
    }
    if (!offline_root(root, FALSE)) {
        fwprintf(stderr, L"Specify the running Windows installation or an offline Windows root.\n");
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) return 1;
    BOOL ok = mmc_approval_edit(algorithm, root, restore);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}
