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

    DWORD slot = NONE;
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
    Output current = {0}, original = {0}, patched = {0};
    BOOL ok = FALSE, staged = FALSE;
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
    } else if (!mmc_approval_stage(stage, saved, replacement, attributes.dwFileAttributes, algorithm)) goto done;
    staged = TRUE;
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
    if (ok) {
        if (restore) wprintf(L"Restored original AppInfo and permissions.\n");
        else wprintf(L"Removed MMC from AppInfo automatic elevation. Original retained at %ls.\n", backup);
    }
done:
    if (!ok) fwprintf(stderr, L"AppInfo operation failed. Preserve any original backup at %ls.\n", backup);
    if (staged && !(restore ? DeleteFileW(stage) : spp_remove(stage)))
        fwprintf(stderr, L"Staged file retained at %ls.\n", stage);
    if (saved != INVALID_HANDLE_VALUE) CloseHandle(saved);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(current.data);
    free(original.data);
    free(patched.data);
    CloseHandle(lock);
    return ok;
}

static int run_mmc_approval(int argc, wchar_t **argv)
{
    wchar_t root[PATH_SIZE];
    if (argc != 3 || !normalize(root, argv[2]) || !offline_root(root, FALSE)) {
        fwprintf(stderr, L"Usage: nttimebomb %ls OFFLINE_WINDOWS_ROOT\n", argv[1]);
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) return 1;
    BOOL ok = mmc_approval_edit(algorithm, root, !_wcsicmp(argv[1], L"/mmc-approval-restore"));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}
