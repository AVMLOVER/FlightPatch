/* cishim's CiGetBuildExpiryTime returns success with a zero output timestamp.
   Independently locate that callback in the original preview image. Keep the
   original CI implementation and all other callbacks intact. No build gate,
   PDB, network access, or replacement kernel module is used at runtime.
   Reference: gailium119/cishim, c0ec25dbcb8e11109e24297c40d72c2ab6b24a8d. */

static BOOL ci_function_range(const Image *im, DWORD offset, DWORD *first, DWORD *last)
{
    DWORD dir = im->pe + 24 + 0x70 + 3 * 8;
    if (!im->x64 || dir + 8 > im->section_table)
        return FALSE;
    DWORD table = translate(im, u32(im->bytes + dir), FALSE, FALSE);
    DWORD size = u32(im->bytes + dir + 4), rva = translate(im, offset, TRUE, TRUE);
    if (table == NONE || size > im->size - table || size % 12 || rva == NONE)
        return FALSE;
    for (DWORD p = table; p < table + size; p += 12) {
        DWORD begin = u32(im->bytes + p), end = u32(im->bytes + p + 4);
        if (begin <= rva && rva < end) {
            *first = translate(im, begin, FALSE, TRUE);
            DWORD tail = end ? translate(im, end - 1, FALSE, TRUE) : NONE;
            if (*first == NONE || tail == NONE || tail < *first ||
                tail - *first != end - begin - 1)
                return FALSE;
            *last = tail + 1;
            return TRUE;
        }
    }
    return FALSE;
}

static DWORD ci_initialize_export(const Image *im)
{
    DWORD dir = im->pe + 24 + (im->x64 ? 0x70 : 0x60);
    if (dir + 8 > im->section_table)
        return NONE;
    DWORD start = translate(im, u32(im->bytes + dir), FALSE, FALSE);
    if (start == NONE || start > im->size - 40)
        return NONE;
    const BYTE *e = im->bytes + start;
    DWORD functions = u32(e + 20), names = u32(e + 24);
    DWORD ft = translate(im, u32(e + 28), FALSE, FALSE);
    DWORD nt = translate(im, u32(e + 32), FALSE, FALSE);
    DWORD ot = translate(im, u32(e + 36), FALSE, FALSE);
    if (ft == NONE || nt == NONE || ot == NONE || names > 4096 ||
        functions > (im->size - ft) / 4 || names > (im->size - nt) / 4 || names > (im->size - ot) / 2)
        return NONE;
    static const char name[] = "CiInitialize";
    for (DWORD i = 0; i < names; ++i) {
        DWORD s = translate(im, u32(im->bytes + nt + i * 4), FALSE, FALSE);
        WORD ordinal = u16(im->bytes + ot + i * 2);
        if (s != NONE && sizeof name <= im->size - s && !memcmp(im->bytes + s, name, sizeof name) &&
            ordinal < functions)
            return translate(im, u32(im->bytes + ft + ordinal * 4), FALSE, TRUE);
    }
    return NONE;
}

static BOOL ci_initializer_calls(const Image *im, DWORD table_function)
{
    DWORD init = ci_initialize_export(im), first, last;
    if (init == NONE || !ci_function_range(im, init, &first, &last))
        return FALSE;
    if (first == table_function)
        return TRUE;
    for (DWORD o = init; o + 5 <= last; ++o)
        if ((im->bytes[o] == 0xe8 || im->bytes[o] == 0xe9) &&
            rel_target(im, o + 5, (int32_t)u32(im->bytes + o + 1)) == table_function)
            return TRUE;
    return FALSE;
}

static DWORD ci_leaf_space(const Image *im)
{
    DWORD dir = im->pe + 24 + 0x70 + 3 * 8;
    DWORD table = translate(im, u32(im->bytes + dir), FALSE, FALSE);
    DWORD size = u32(im->bytes + dir + 4);
    if (table == NONE || size > im->size - table || size % 12)
        return NONE;
    for (DWORD p = table; p < table + size; p += 12) {
        DWORD end = u32(im->bytes + p + 4);
        if (end > UINT32_MAX - 15)
            continue;
        DWORD rva = (end + 15) & ~15u;
        DWORD raw = translate(im, rva, FALSE, TRUE), first, last;
        if (raw == NONE || !code_span(im, raw, 7) ||
            !at(im, raw, "\xcc\xcc\xcc\xcc\xcc\xcc\xcc", "xxxxxxx") ||
            ci_function_range(im, raw, &first, &last) ||
            ci_function_range(im, raw + 6, &first, &last))
            continue;
        return raw;
    }
    return NONE;
}

static BOOL plan_ci_expiry(const Image *im, Plan *plan)
{
    static const wchar_t path[] = L"\\SystemRoot\\System32\\ci.dll";
    static const char leaf[] = "\x48\x83\x21\x00\x33\xc0\xc3";
    DWORD literal = unique_data(im, path, sizeof path);
    if (literal == NONE) {
        for (DWORD o = 0; o + sizeof path <= im->size; ++o)
            if (!memcmp(im->bytes + o, path, sizeof path))
                return FALSE; /* A duplicate/unmapped anchor is not an old layout. */
        return plan_ci(im, plan); /* Earlier FlightSigned CI layouts. */
    }
    if (!im->x64)
        return FALSE; /* A preview x86 expiry callback needs its own verified ABI. */
    DWORD path_rva = translate(im, literal, TRUE, FALSE), function = NONE, function_end = 0;
    unsigned references_found = 0;
    for (DWORD o = 0; o + 7 <= im->size; ++o) {
        DWORD first, last;
        if (!code_span(im, o, 7) || !references(im, o, path_rva, FALSE) ||
            !ci_function_range(im, o, &first, &last) || o - first > 256)
            continue;
        if (function != NONE && function != first)
            return FALSE;
        function = first;
        function_end = last;
        ++references_found;
    }
    if (!references_found || function == NONE)
        return FALSE;
    DWORD target_rva = translate(im, function, TRUE, TRUE);
    unsigned callbacks = 0;
    for (DWORD o = 0; o + 14 <= im->size; ++o) {
        DWORD first, last;
        if (!at(im, o, "\x48\x8d\x05\0\0\0\0\x48\x89", "xxx????xx") ||
            (im->bytes[o + 9] & 0xf8) != 0x80 ||
            (u32(im->bytes + o + 10) != 0xb0 && u32(im->bytes + o + 10) != 0xb8) ||
            !code_span(im, o, 14) ||
            (int64_t)translate(im, o, TRUE, TRUE) + 7 + (int32_t)u32(im->bytes + o + 3) != target_rva ||
            !ci_function_range(im, o, &first, &last) || !ci_initializer_calls(im, first))
            continue;
        ++callbacks;
    }
    if (callbacks != 1)
        return FALSE;
    DWORD leaf_offset;
    if (im->bytes[function] == 0xe9) {
        leaf_offset = rel_target(im, function + 5, (int32_t)u32(im->bytes + function + 1));
        DWORD first, last;
        if (leaf_offset == NONE || !code_span(im, leaf_offset, 7) ||
            !at(im, leaf_offset, leaf, "xxxxxxx") || ci_function_range(im, leaf_offset, &first, &last) ||
            ci_function_range(im, leaf_offset + 6, &first, &last))
            return FALSE;
    } else {
        /* Both verified preview callbacks start by saving RBX in five bytes.
           Redirect before that prologue runs, so original unwind/CFG metadata
           remains valid. The new leaf lives in verified INT3 alignment padding. */
        if (function_end - function < 32 ||
            !at(im, function, "\x48\x89\x5c\x24", "xxxx") ||
            (leaf_offset = ci_leaf_space(im)) == NONE)
            return FALSE;
    }
    int64_t displacement = (int64_t)translate(im, leaf_offset, TRUE, TRUE) - target_rva - 5;
    if (displacement < INT32_MIN || displacement > INT32_MAX)
        return FALSE;
    char jump[5] = {0xe9};
    int32_t relative = (int32_t)displacement;
    memcpy(jump + 1, &relative, sizeof relative);
    return record(im, plan, leaf_offset, leaf, sizeof leaf - 1, L"CI zero-expiry leaf") &&
           record(im, plan, function, jump, sizeof jump, L"CI build-expiry callback");
}

static BOOL ci_original_backup(OfflineEdit *edit, BCRYPT_ALG_HANDLE algorithm)
{
    wchar_t path[PATH_SIZE];
    if (swprintf(path, PATH_SIZE, L"%ls.nttp-original", edit->path) < 0 || !spp_path_type(path, FALSE, TRUE))
        return FALSE;
    HANDLE backup = spp_open(path, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, CREATE_NEW);
    if (backup == INVALID_HANDLE_VALUE) {
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS)
            return FALSE;
        backup = spp_open(path, GENERIC_READ, OPEN_EXISTING);
        Output original = {0};
        BOOL ok = backup != INVALID_HANDLE_VALUE && offline_read(backup, &original, algorithm) &&
                  !strcmp(original.sha, edit->before.sha);
        free(original.data);
        if (backup != INVALID_HANDLE_VALUE)
            CloseHandle(backup);
        if (!ok)
            fwprintf(stderr, L"Existing CI backup differs from the unpatched input: %ls. Preserve it separately before retrying.\n", path);
        return ok;
    }
    LARGE_INTEGER start = {0};
    BOOL ok = SetFilePointerEx(edit->file, start, NULL, FILE_BEGIN) &&
              spp_copy_verified(edit->file, backup) && spp_restore_metadata(edit->file, backup) == ERROR_SUCCESS;
    CloseHandle(backup);
    if (!ok)
        DeleteFileW(path);
    else
        wprintf(L"Original CI and permissions retained at %ls.\n", path);
    return ok;
}

static BOOL patch_ci_only(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root)
{
    wchar_t scope[OFFLINE_NT_PATH], live_final[OFFLINE_NT_PATH], live[PATH_SIZE], final[OFFLINE_NT_PATH];
    OfflineEdit edit = {0};
    UINT length = GetSystemWindowsDirectoryW(live, PATH_SIZE);
    if (!length || length >= PATH_SIZE || !offline_root(root, FALSE) ||
        !offline_directory(root, scope) || !offline_directory(live, live_final) ||
        !build_path(edit.path, root, L"Windows\\System32\\ci.dll") || !spp_path_chain(edit.path, FALSE))
        return FALSE;
    edit.file = spp_open(edit.path, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    BOOL ok = edit.file != INVALID_HANDLE_VALUE && GetFileInformationByHandle(edit.file, &edit.id) &&
              offline_path_name(edit.file, final) && offline_under(final, scope) &&
              !offline_under(final, live_final) && offline_read(edit.file, &edit.before, algorithm);
    /* Canonical paths alone do not distinguish a hardlink to the live CI. */
    wchar_t live_ci[PATH_SIZE];
    BOOL wow = FALSE;
    BOOL native_path = sizeof(void *) == 4 && IsWow64Process(GetCurrentProcess(), &wow) && wow;
    if (ok && build_path(live_ci, live, native_path ? L"Sysnative\\ci.dll" : L"System32\\ci.dll")) {
        HANDLE current = spp_open(live_ci, FILE_READ_ATTRIBUTES, OPEN_EXISTING);
        BY_HANDLE_FILE_INFORMATION id;
        ok = current != INVALID_HANDLE_VALUE && GetFileInformationByHandle(current, &id) &&
             !offline_file_id(&edit.id, &id);
        if (current != INVALID_HANDLE_VALUE)
            CloseHandle(current);
    } else {
        ok = FALSE;
    }
    if (ok) {
        edit.after.size = edit.before.size;
        edit.after.data = malloc(edit.after.size);
        ok = edit.after.data != NULL;
    }
    Plan plan = {0};
    if (ok) {
        memcpy(edit.after.data, edit.before.data, edit.after.size);
        Image image;
        ok = image_open(&image, edit.after.data, edit.after.size) && plan_ci_expiry(&image, &plan) &&
             (plan.count || plan.existing);
        if (!ok)
            fwprintf(stderr, L"Unsupported or ambiguous CI expiry structure in %ls. No files changed.\n", edit.path);
    }
    for (unsigned i = 0; ok && i < plan.count; ++i) {
        Change *change = &plan.edits[i];
        memcpy(edit.after.data + change->at, change->bytes, change->length);
        wprintf(L"  %06lX  %ls\n", change->at, change->label);
    }
    if (ok && plan.count) {
        ok = fix_checksum(edit.after.data, edit.after.size) &&
             digest(algorithm, edit.after.data, edit.after.size, edit.after.sha) &&
             ci_original_backup(&edit, algorithm) && offline_lock(&edit, algorithm);
        if (ok) {
            edit.touched = TRUE;
            ok = offline_write(&edit, &edit.after, algorithm);
        }
    }
    if (!ok && edit.touched && !offline_write(&edit, &edit.before, algorithm))
        fwprintf(stderr, L"CI rollback failed. Restore the retained .nttp-original backup for %ls.\n", edit.path);
    if (edit.restore_readonly && !(edit.writable ? offline_readonly(edit.file, TRUE) : offline_reopen_readonly(edit.file, TRUE)))
        ok = FALSE;
    if (edit.file != INVALID_HANDLE_VALUE)
        CloseHandle(edit.file);
    free(edit.after.data);
    free(edit.before.data);
    if (ok)
        wprintf(plan.count ? L"CI-only patch verified in %ls. No build-number check was used.\n" :
                            L"CI-only patch is already present in %ls. No files changed.\n", root);
    return ok;
}
