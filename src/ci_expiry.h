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

static int32_t arm_signed(DWORD value, unsigned bits)
{
    DWORD sign = 1u << (bits-1);
    return (int32_t)((value ^ sign) - sign);
}

static DWORD arm_bl(const Image *im, DWORD offset)
{
    DWORD word = u32(im->bytes + offset);
    DWORD rva = translate(im, offset, TRUE, TRUE);
    if ((word & 0xfc000000) != 0x94000000 || rva == NONE) return NONE;
    return translate(im, rva + arm_signed(word & 0x3ffffff, 26) * 4, FALSE, TRUE);
}

static BOOL arm_ci_zero(const Image *im, Plan *plan)
{
    DWORD entry = ci_initialize_export(im);
    if (entry == NONE || !code_span(im, entry, 128)) return FALSE;
    DWORD dir = im->pe + 24 + 0x70 + 24;
    if (dir + 8 > im->section_table) return FALSE;
    DWORD table = translate(im, u32(im->bytes+dir), FALSE, FALSE);
    DWORD size = u32(im->bytes+dir+4);
    if (table == NONE || size > im->size-table || size % 8) return FALSE;

    unsigned found = 0;
    for (DWORD off = entry; off < entry+128; off += 4) {
        if (u32(im->bytes+off) == 0xd65f03c0) break;
        DWORD start = arm_bl(im, off);
        if (start == NONE) continue;
        DWORD rva = translate(im, start, TRUE, TRUE);
        for (DWORD p = table; p < table+size; p += 8) {
            if (u32(im->bytes+p) != rva) continue;
            DWORD unwind = u32(im->bytes+p+4), words;
            if (unwind & 3) words = (unwind >> 2) & 0x7ff;
            else {
                DWORD xdata = translate(im, unwind, FALSE, FALSE);
                if (xdata == NONE || xdata > im->size-4) break;
                words = u32(im->bytes+xdata) & 0x3ffff;
            }
            if (!code_span(im, start, words*4)) break;
            for (DWORD o = start; o+12 <= start+words*4; o += 4) {
                DWORD adrp = u32(im->bytes+o), add = u32(im->bytes+o+4), store = u32(im->bytes+o+8);
                if ((adrp & 0x9f000000) != 0x90000000 || (add & 0xffc00000) != 0x91000000 ||
                    ((add >> 5) & 31) != (adrp & 31) || (store & 0xffc00000) != 0xa9000000 ||
                    ((store >> 10) & 31) != (add & 31) || ((store >> 15) & 127) != 0xa8/8) continue;
                DWORD imm = ((adrp >> 5) & 0x7ffff)*4 + ((adrp >> 29) & 3);
                DWORD target = (DWORD)((translate(im, o, TRUE, TRUE) & ~4095u) +
                    (int64_t)arm_signed(imm,21)*4096 + ((add>>10)&4095));
                DWORD leaf = translate(im, target, FALSE, TRUE);
                if (leaf != NONE && code_span(im, leaf, 12) &&
                    u32(im->bytes+leaf)==0xf900001f && u32(im->bytes+leaf+4)==0x52800000 &&
                    u32(im->bytes+leaf+8)==0xd65f03c0) ++found;
            }
            break;
        }
    }
    if (found != 1) return FALSE;
    ++plan->existing;
    return TRUE;
}

static BOOL plan_ci_expiry(const Image *im, Plan *plan)
{
    if (im->machine == IMAGE_FILE_MACHINE_ARM64)
        return arm_ci_zero(im, plan);
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

static BOOL plan_ci_boot(const Image *im, Plan *plan)
{
    if (!im->x64 || u16(im->bytes + im->pe + 24 + 0x44) != IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
        return FALSE;

    /* OslPrepareTarget removes two options from the same application entry.
       Keep DisableIntegrityChecks (0x16000048) if explicitly set in BCD.
       Leave the removal of DisableElamDrivers and the load-options sanitizer intact. */
    const BYTE *bytes = im->bytes;
    DWORD found = NONE;
    if (im->machine == IMAGE_FILE_MACHINE_ARM64) {
        const DWORD expected[] = {0x16000048, 0x260000e1, 0x12000030};
        const unsigned literal[] = {4, 20, 44};
        for (DWORD o = 0; o+52 <= im->size; o += 4) {
            if (u32(bytes+o+8) != 0xf9400c00 || u32(bytes+o+24) != 0xf9400c00 ||
                u32(bytes+o+40) != 0xf9400c00 || (u32(bytes+o+36) & 0xffc003ff) != 0x910003e2 ||
                !code_span(im,o,52)) continue;
            DWORD getter = arm_bl(im,o), remove = arm_bl(im,o+28), read = arm_bl(im,o+48);
            if (getter == NONE || remove == NONE || read == NONE || getter == remove || getter == read || remove == read ||
                arm_bl(im,o+16)!=getter || arm_bl(im,o+32)!=getter ||
                (arm_bl(im,o+12)!=remove && u32(bytes+o+12)!=0xd503201f)) continue;
            BOOL valid = TRUE;
            for (unsigned i=0;i<ARRAYSIZE(expected);++i) {
                DWORD op = u32(bytes+o+literal[i]);
                DWORD rva = translate(im,o+literal[i],TRUE,TRUE);
                DWORD data = translate(im,rva+arm_signed((op>>5)&0x7ffff,19)*4,FALSE,FALSE);
                if ((op & 0xff00001f)!=0x18000001 || data==NONE || data>im->size-4 || u32(bytes+data)!=expected[i]) {
                    valid = FALSE;
                    break;
                }
            }
            if (valid) {
                if (found != NONE) return FALSE;
                found = o+12;
            }
        }
        return found != NONE && record(im, plan, found, "\x1f\x20\x03\xd5", 4,
                                      L"keep the ARM64 loader's BCD nointegritychecks option");
    }
    for (DWORD offset = 0; offset + 61 <= im->size; ++offset) {
        /* Later loaders obtain the application entry from the same getter before each option. */
        if (at(im, offset, "\xe8\0\0\0\0\xba\x48\x00\x00\x16\x48\x8b\x48\x18", "x????xxxxxxxxx") &&
            at(im, offset + 19, "\xe8\0\0\0\0\xba\xe1\x00\x00\x26\x48\x8b\x48\x18\xe8", "x????xxxxxxxxxx") &&
            at(im, offset + 38, "\xe8\0\0\0\0\xbf\x30\x00\x00\x12\x4c\x8d\x45\0\x8b\xd7\x48\x8b\x48\x18\xe8",
                "x????xxxxxxxx?xxxxxxx") && code_span(im, offset, 63)) {
            DWORD getter = rel_target(im, offset + 5, (int32_t)u32(bytes + offset + 1));
            DWORD remove = rel_target(im, offset + 38, (int32_t)u32(bytes + offset + 34));
            DWORD read = rel_target(im, offset + 63, (int32_t)u32(bytes + offset + 59));
            if (getter != NONE && remove != NONE && read != NONE && getter != remove && getter != read && remove != read &&
                getter == rel_target(im, offset + 24, (int32_t)u32(bytes + offset + 20)) &&
                getter == rel_target(im, offset + 43, (int32_t)u32(bytes + offset + 39)) &&
                (all_nops(bytes + offset + 14, 5) ||
                 (bytes[offset + 14] == 0xe8 && remove == rel_target(im, offset + 19, (int32_t)u32(bytes + offset + 15))))) {
                if (found != NONE) return FALSE;
                found = offset + 14;
            }
        }
        if (!at(im, offset, "\x48\x8b\x0d\0\0\0\0\xba\x48\x00\x00\x16\x48\x89\x5d", "xxx????xxxxxxxx") ||
            !at(im, offset + 21, "\x48\x8b\x0d\0\0\0\0\xba\xe1\x00\x00\x26\xe8", "xxx????xxxxxx") ||
            !at(im, offset + 38, "\x48\x8b\x0d\0\0\0\0\x4c\x8d\x45\0\xbe\x30\x00\x00\x12\x8b\xd6\xe8", "xxx????xxx?xxxxxxxx") ||
            bytes[offset + 15] != bytes[offset + 48] || !code_span(im, offset, 61))
            continue;

        /* The RIP-relative references at the three loads must resolve to the same slot. */
        int64_t slot = 7 + (int64_t)(int32_t)u32(bytes + offset + 3);
        if (slot != 28 + (int64_t)(int32_t)u32(bytes + offset + 24) ||
            slot != 45 + (int64_t)(int32_t)u32(bytes + offset + 41))
            continue;

        DWORD remove_option = rel_target(im, offset + 38, (int32_t)u32(bytes + offset + 34));
        DWORD read_option = rel_target(im, offset + 61, (int32_t)u32(bytes + offset + 57));
        if (remove_option == NONE || read_option == NONE || read_option == remove_option ||
            (!all_nops(bytes + offset + 16, 5) &&
             (bytes[offset + 16] != 0xe8 || rel_target(im, offset + 21, (int32_t)u32(bytes + offset + 17)) != remove_option)))
            continue;
        if (found != NONE)
            return FALSE;
        found = offset + 16;
    }
    return found != NONE && record(im, plan, found, "\x90\x90\x90\x90\x90", 5,
                                   L"keep the loader's BCD nointegritychecks option");
}

static BOOL ci_io_error(const wchar_t *action, const wchar_t *path, DWORD error)
{
    fwprintf(stderr, L"Cannot %ls %ls (Win32 %lu).\n", action, path, error);
    if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
        privilege_hint();
    return FALSE;
}

static BOOL ci_original_backup(OfflineEdit *edit, BCRYPT_ALG_HANDLE algorithm)
{
    wchar_t path[PATH_SIZE];
    if (swprintf(path, PATH_SIZE, L"%ls.nttp-original", edit->path) < 0 || !spp_path_type(path, FALSE, TRUE))
        return FALSE;
    HANDLE backup = spp_open(path, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, CREATE_NEW);
    if (backup == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            return ci_io_error(L"create backup", path, error);
        backup = spp_open(path, GENERIC_READ, OPEN_EXISTING);
        if (backup == INVALID_HANDLE_VALUE)
            return ci_io_error(L"open existing backup", path, GetLastError());
        Output original = {0};
        BOOL ok = offline_read(backup, &original, algorithm) && !strcmp(original.sha, edit->before.sha);
        free(original.data);
        CloseHandle(backup);
        if (!ok)
            fwprintf(stderr, L"Existing backup differs from the unpatched input: %ls. Preserve it separately before retrying.\n", path);
        return ok;
    }
    LARGE_INTEGER start = {0};
    BOOL ok = SetFilePointerEx(edit->file, start, NULL, FILE_BEGIN) &&
              spp_copy_verified(edit->file, backup) && spp_restore_metadata(edit->file, backup) == ERROR_SUCCESS;
    CloseHandle(backup);
    if (!ok)
        DeleteFileW(path);
    else
        wprintf(L"Original file and permissions retained at %ls.\n", path);
    return ok;
}

static BOOL ci_check_live_file(const OfflineEdit *edit, const wchar_t *live, const wchar_t *name,
                               const BY_HANDLE_FILE_INFORMATION *live_dir)
{
    /* A single link outside the live tree, or a different volume, rules out an alias.
       WinPE does not always have this boot file at the live System32 path. */
    if (edit->id.nNumberOfLinks == 1 || edit->id.dwVolumeSerialNumber != live_dir->dwVolumeSerialNumber)
        return TRUE;

    wchar_t relative[48], path[PATH_SIZE];
    BOOL wow = FALSE;
    BOOL native_path = sizeof(void *) == 4 && IsWow64Process(GetCurrentProcess(), &wow) && wow;
    if (swprintf(relative, 48, L"%ls\\%ls", native_path ? L"Sysnative" : L"System32", name) < 0 ||
        !build_path(path, live, relative))
        return ci_io_error(L"resolve the live file to compare with", edit->path, ERROR_FILENAME_EXCED_RANGE);
    HANDLE current = spp_open(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING);
    if (current == INVALID_HANDLE_VALUE)
        return ci_io_error(L"check the live file for a hard link", path, GetLastError());
    BY_HANDLE_FILE_INFORMATION id;
    BOOL inspected = GetFileInformationByHandle(current, &id);
    DWORD error = GetLastError();
    CloseHandle(current);
    if (!inspected)
        return ci_io_error(L"read the identity of", path, error);
    if (offline_file_id(&edit->id, &id)) {
        fwprintf(stderr, L"Target is a hard link to the running Windows file %ls.\n", path);
        return FALSE;
    }
    return TRUE;
}

typedef struct {
    const wchar_t *root;
    wchar_t root_final[OFFLINE_NT_PATH], live_final[OFFLINE_NT_PATH], live[PATH_SIZE];
    BY_HANDLE_FILE_INFORMATION live_dir;
} CiScope;

typedef enum { CI_ERROR, CI_READY, CI_ARM64_ZERO } CiProbe;

static CiProbe ci_prepare(BCRYPT_ALG_HANDLE algorithm, const CiScope *scope,
                          OfflineEdit *edit, BOOL loader)
{
    const wchar_t *name = loader ? L"winload.efi" : L"ci.dll";
    wchar_t relative[48], final[OFFLINE_NT_PATH];
    if (swprintf(relative, 48, L"Windows\\System32\\%ls", name) < 0 ||
        !build_path(edit->path, scope->root, relative) || !spp_path_chain(edit->path, FALSE)) {
        fwprintf(stderr, L"Cannot resolve a safe offline %ls path under %ls.\n", name, scope->root);
        return CI_ERROR;
    }
    edit->file = spp_open(edit->path, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    if (edit->file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        ci_io_error(L"open offline target", edit->path, error);
        return CI_ERROR;
    }
    if (!GetFileInformationByHandle(edit->file, &edit->id) || !offline_path_name(edit->file, final)) {
        ci_io_error(L"resolve the identity of", edit->path, GetLastError());
        return CI_ERROR;
    }
    if (!offline_under(final, scope->root_final) || offline_under(final, scope->live_final)) {
        fwprintf(stderr, L"Target resolves outside the offline Windows root or inside running Windows: %ls.\n", edit->path);
        return CI_ERROR;
    }
    if (!ci_check_live_file(edit, scope->live, name, &scope->live_dir))
        return CI_ERROR;
    if (!offline_read(edit->file, &edit->before, algorithm)) {
        fwprintf(stderr, L"Cannot read or verify offline target %ls.\n", edit->path);
        return CI_ERROR;
    }

    Image image;
    Plan plan = {0};
    if (!image_open_arch(&image, edit->before.data, edit->before.size, TRUE) ||
        !(loader ? plan_ci_boot(&image, &plan) : plan_ci_expiry(&image, &plan)) ||
        !(plan.count || plan.existing)) {
        fwprintf(stderr, L"Unsupported or ambiguous %ls structure in %ls. No files changed.\n",
                 loader ? L"UEFI loader" : L"CI expiry", edit->path);
        return CI_ERROR;
    }
    if (!loader && image.machine == IMAGE_FILE_MACHINE_ARM64)
        return CI_ARM64_ZERO;
    if (!plan.count)
        return CI_READY;

    edit->after.size = edit->before.size;
    edit->after.data = malloc(edit->after.size);
    if (!edit->after.data) {
        fwprintf(stderr, L"Cannot allocate a patch buffer for %ls.\n", edit->path);
        return CI_ERROR;
    }
    memcpy(edit->after.data, edit->before.data, edit->after.size);
    for (unsigned i = 0; i < plan.count; ++i) {
        Change *change = &plan.edits[i];
        memcpy(edit->after.data + change->at, change->bytes, change->length);
        wprintf(L"  %06lX  %ls\n", change->at, change->label);
    }
    if (!fix_checksum(edit->after.data, edit->after.size) ||
        !digest(algorithm, edit->after.data, edit->after.size, edit->after.sha)) {
        fwprintf(stderr, L"Cannot verify the prepared patch for %ls.\n", edit->path);
        return CI_ERROR;
    }
    edit->after.changed = TRUE;
    return CI_READY;
}

static BOOL patch_ci_file(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root, BOOL loader_only)
{
    CiScope scope = {.root = root};
    UINT length = GetSystemWindowsDirectoryW(scope.live, PATH_SIZE);
    if (!length || length >= PATH_SIZE || !offline_root(root, FALSE) ||
        !offline_directory(root, scope.root_final) ||
        !offline_directory_info(scope.live, scope.live_final, &scope.live_dir)) {
        fwprintf(stderr, L"Cannot resolve a safe offline Windows root at %ls.\n", root);
        return FALSE;
    }

    /* The loader is written first. Prepare and lock both files before writing either. */
    enum { CI_LOADER, CI_BINARY, CI_FILES };
    OfflineEdit edits[CI_FILES] = {
        [CI_LOADER] = {.file = INVALID_HANDLE_VALUE},
        [CI_BINARY] = {.file = INVALID_HANDLE_VALUE},
    };
    CiProbe ci = loader_only ? CI_READY : ci_prepare(algorithm, &scope, &edits[CI_BINARY], FALSE);
    if (ci == CI_ARM64_ZERO) {
        CloseHandle(edits[CI_BINARY].file);
        free(edits[CI_BINARY].before.data);
        wprintf(L"ARM64 CI expiry already returns zero. No files changed.\n");
        return TRUE;
    }
    CiProbe loader = ci == CI_READY ? ci_prepare(algorithm, &scope, &edits[CI_LOADER], TRUE) : CI_ERROR;
    BOOL ok = ci == CI_READY && loader == CI_READY;
    if (ok && !loader_only) {
        const BYTE *left = edits[CI_BINARY].before.data, *right = edits[CI_LOADER].before.data;
        ok = u16(left+u32(left+0x3c)+4) == u16(right+u32(right+0x3c)+4);
        if (!ok) fwprintf(stderr,L"CI and the UEFI loader have different architectures. No files changed.\n");
    }

    for (unsigned i = 0; ok && i < CI_FILES; ++i) {
        OfflineEdit *edit = &edits[i];
        if (edit->after.changed && (!ci_original_backup(edit, algorithm) || !offline_lock(edit, algorithm))) {
            fwprintf(stderr, L"Patch preparation failed for %ls. The target contents were not written.\n", edit->path);
            ok = FALSE;
        }
    }
    for (unsigned i = 0; ok && i < CI_FILES; ++i) {
        OfflineEdit *edit = &edits[i];
        if (!edit->after.changed)
            continue;
        edit->touched = TRUE;
        ok = offline_write(edit, &edit->after, algorithm);
        if (!ok)
            ci_io_error(L"write and verify", edit->path, GetLastError());
    }

    BOOL metadata_ok = TRUE;
    for (unsigned i = CI_FILES; i > 0; --i) {
        OfflineEdit *edit = &edits[i - 1];
        if (!ok && edit->touched && !offline_write(edit, &edit->before, algorithm))
            fwprintf(stderr, L"Rollback failed. Restore the retained .nttp-original backup for %ls.\n", edit->path);
        if (edit->restore_readonly && !(edit->writable ? offline_readonly(edit->file, TRUE) : offline_reopen_readonly(edit->file, TRUE)))
            metadata_ok = ci_io_error(L"restore the read-only attribute of", edit->path, GetLastError());
        if (edit->file != INVALID_HANDLE_VALUE)
            CloseHandle(edit->file);
        free(edit->after.data);
        free(edit->before.data);
    }
    if (!ok || !metadata_ok)
        return FALSE;

    if (!loader_only)
        wprintf(edits[CI_BINARY].after.changed ? L"CI patch verified in %ls.\n" : L"CI patch already present in %ls.\n", root);
    if (loader == CI_READY) {
        wprintf(edits[CI_LOADER].after.changed ? L"UEFI loader patch verified in %ls.\n" :
                                                L"UEFI loader patch already present in %ls.\n", root);
        wprintf(L"Before rebooting, set nointegritychecks on for the target Windows BCD entry, with Secure Boot off.\n"
                L"Example: bcdedit /store S:\\EFI\\Microsoft\\Boot\\BCD /set {default} nointegritychecks on\n");
    }
    return TRUE;
}
