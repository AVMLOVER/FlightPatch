/* Structural matchers for early Flightsigned x86 and AMD64 images. */
typedef struct {
    BYTE *bytes;
    DWORD size;
    DWORD pe;
    DWORD section_table;
    WORD sections;
    BOOL x64;
} Image;

enum { NONE = UINT32_MAX, MAX_EDITS = 32 };

typedef struct {
    DWORD at;
    BYTE length;
    BYTE bytes[40];
    const wchar_t *label;
} Change;

typedef struct {
    Change edits[MAX_EDITS];
    unsigned count;
    unsigned existing;
} Plan;

static uint32_t u32(const void *data)
{
    uint32_t value;
    memcpy(&value, data, sizeof value);
    return value;
}

static uint16_t u16(const void *data)
{
    uint16_t value;
    memcpy(&value, data, sizeof value);
    return value;
}

static BOOL image_open(Image *im, BYTE *bytes, DWORD size)
{
    if (size < 0x100 || memcmp(bytes, "MZ", 2))
        return FALSE;
    DWORD pe = u32(bytes + 0x3c);
    if (pe > size - 0x60 || u32(bytes + pe) != IMAGE_NT_SIGNATURE)
        return FALSE;
    WORD machine = u16(bytes + pe + 4), sections = u16(bytes + pe + 6);
    WORD opt = u16(bytes + pe + 20), magic = u16(bytes + pe + 24);
    BOOL x64 = machine == IMAGE_FILE_MACHINE_AMD64 && magic == 0x20b;
    if ((!x64 && !(machine == IMAGE_FILE_MACHINE_I386 && magic == 0x10b)) ||
        opt < (x64 ? 0x70 : 0x60) || !sections || sections > 96)
        return FALSE;
    DWORD table = pe + 24 + opt;
    if (table < pe || table > size || sections > (size - table) / 40)
        return FALSE;
    for (unsigned i = 0; i < sections; ++i) {
        BYTE *s = bytes + table + i * 40;
        DWORD start = u32(s + 20), length = u32(s + 16);
        if (start > size || length > size - start || u32(s + 12) > UINT32_MAX - length)
            return FALSE;
    }
    *im = (Image){bytes, size, pe, table, sections, x64};
    return TRUE;
}

static DWORD translate(const Image *im, DWORD address, BOOL to_rva, BOOL executable)
{
    for (unsigned i = 0; i < im->sections; ++i) {
        const BYTE *s = im->bytes + im->section_table + i * 40;
        DWORD raw = u32(s + 20), rva = u32(s + 12), length = u32(s + 16);
        DWORD start = to_rva ? raw : rva;
        if (address >= start && address - start < length &&
            (!executable || (u32(s + 36) & IMAGE_SCN_MEM_EXECUTE)))
            return (to_rva ? rva : raw) + address - start;
    }
    return NONE;
}

static BOOL code_span(const Image *im, DWORD offset, unsigned length)
{
    if (!length || offset >= im->size || length > im->size - offset)
        return FALSE;
    DWORD first = translate(im, offset, TRUE, TRUE);
    return first != NONE && translate(im, offset + length - 1, TRUE, TRUE) == first + length - 1;
}

static DWORD rel_target(const Image *im, DWORD next, int32_t disp)
{
    DWORD rva = translate(im, next - 1, TRUE, TRUE);
    if (rva == NONE)
        return NONE;
    int64_t target = (int64_t)rva + 1 + disp;
    return target < 0 || target >= NONE ? NONE : translate(im, (DWORD)target, FALSE, TRUE);
}

/* NUL ends the mask, '?' is a wildcard. */
static BOOL at(const Image *im, DWORD pos, const char *bytes, const char *mask)
{
    size_t len = strlen(mask);
    if (pos >= im->size || len > im->size - pos)
        return FALSE;
    for (size_t i = 0; i < len; ++i)
        if (mask[i] != '?' && im->bytes[pos + i] != (BYTE)bytes[i])
            return FALSE;
    return TRUE;
}

static BOOL all_nops(const BYTE *p, unsigned length)
{
    for (unsigned i = 0; i < length; ++i)
        if (p[i] != 0x90)
            return FALSE;
    return TRUE;
}

static BOOL record(const Image *im, Plan *plan, DWORD at_offset, const char *bytes,
                   unsigned length, const wchar_t *label)
{
    if (length > sizeof plan->edits[0].bytes || !code_span(im, at_offset, length))
        return FALSE;
    if (!memcmp(im->bytes + at_offset, bytes, length)) {
        ++plan->existing;
        return TRUE;
    }
    if (plan->count == MAX_EDITS)
        return FALSE;
    for (unsigned i = 0; i < plan->count; ++i) {
        const Change *e = &plan->edits[i];
        if (at_offset < e->at + e->length && e->at < at_offset + length)
            return FALSE;
    }
    Change *edit = &plan->edits[plan->count++];
    *edit = (Change){.at=at_offset, .length=(BYTE)length, .label=label};
    memcpy(edit->bytes, bytes, length);
    return TRUE;
}

static DWORD unique_data(const Image *im, const void *needle, unsigned length)
{
    DWORD found = NONE;
    const BYTE *start = im->bytes;
    const BYTE *end = start + im->size - length + 1;
    while (start < end) {
        const BYTE *p = memchr(start, *(const BYTE *)needle, end - start);
        if (!p)
            break;
        DWORD offset = (DWORD)(p - im->bytes);
        if (!memcmp(p, needle, length) && translate(im, offset, TRUE, FALSE) != NONE) {
            if (found != NONE)
                return NONE;
            found = offset;
        }
        start = p + 1;
    }
    return found;
}

static BOOL references(const Image *im, DWORD offset, DWORD target_rva, BOOL wide_string)
{
    const BYTE *p = im->bytes + offset;
    if (im->x64) {
        return (p[0] & 0xf8) == 0x48 && p[1] == 0x8d && (p[2] & 0xc7) == 5 &&
               (int64_t)translate(im, offset, TRUE, TRUE) + 7 +
               (int32_t)u32(p + 3) == target_rva;
    }
    if (wide_string && p[0] != 0x68)
        return FALSE;
    if (!wide_string && p[0] != 0xba && !(p[0] == 0xc7 && p[1] == 0x45))
        return FALSE;
    unsigned imm = p[0] == 0xc7 ? 3 : 1;
    return (uint64_t)u32(im->bytes + im->pe + 52) + target_rva == u32(p + imm);
}

static BOOL unwind_entry(const Image *im, DWORD offset)
{
    DWORD entry = translate(im, offset, TRUE, TRUE);
    DWORD dir = im->pe + 24 + 0x70 + 3 * 8;
    if (dir + 8 > im->section_table)
        return FALSE;
    DWORD pdata = translate(im, u32(im->bytes + dir), FALSE, FALSE);
    DWORD size = u32(im->bytes + dir + 4);
    if (pdata == NONE || size > im->size - pdata || size % 12)
        return FALSE;
    for (DWORD p = pdata; p < pdata + size; p += 12)
        if (u32(im->bytes + p) == entry)
            return TRUE;
    return FALSE;
}

static BOOL hash_anchor(const Image *im, DWORD function, DWORD oid_rva)
{
    if (function == NONE || !code_span(im, function, 256) || (im->x64 && !unwind_entry(im, function)))
        return FALSE;
    if (!im->x64 &&
        !at(im, function, "\x8b\xff\x55\x8b\xec", "xxxxx") &&
        !at(im, function, "\x55\x8b\xec", "xxx"))
        return FALSE;
    for (DWORD o = function; o < function + 249; ++o)
        if (references(im, o, oid_rva, FALSE))
            return TRUE;
    return FALSE;
}

static BOOL flag_branch(const Image *im, DWORD branch, unsigned length)
{
    const BYTE *p = im->bytes + branch;
    if (all_nops(p, length))
        return TRUE;
    if (length == 2 && p[0] == 0x75)
        return rel_target(im, branch + 2, (int8_t)p[1]) != NONE;
    return length == 6 && p[0] == 0x0f && p[1] == 0x85 &&
           rel_target(im, branch + 6, (int32_t)u32(p + 2)) != NONE;
}

static BOOL find_main_hash(const Image *im, DWORD oid, DWORD *hash, DWORD *filter,
                           DWORD *branch, unsigned *length)
{
    unsigned count = 0;
    const BYTE *b = im->bytes;
    for (DWORD o = 0; o + 64 < im->size; ++o) {
        BOOL x64 = im->x64;
        if (b[o] != 0xe8 ||
            !(x64 ? at(im, o + 5, "\x8b\xd8\x85\xc0\x79\0\0\x8b\xc6\x8b\xd0\x49\x8b\xcf\xe8", "xxxxx??xxxxxxxx")
                  : at(im, o + 5, "\x8b\xf0\x85\xf6\x79\0\x8b\x4d\x08\x8b\xd6\x53\xe8", "xxxxx?xxxxxxx")) ||
            !code_span(im, o, 64))
            continue;
        DWORD target = rel_target(im, o + 5, (int32_t)u32(b + o + 1));
        if (!hash_anchor(im, target, oid))
            continue;
        DWORD fcall = o + (x64 ? 19 : 17);
        DWORD ftarget = rel_target(im, fcall + 5, (int32_t)u32(b + fcall + 1));
        if (ftarget == NONE)
            continue;
        DWORD success = rel_target(im, o + 11, (int8_t)b[o + 10]);
        DWORD guard = fcall + (x64 ? (b[fcall + 5] == 0x45 ? 8 : 7) : 5);
        if (!at(im, guard, x64 ? "\x8b\xd8\x85\xc0\x79" : "\x8b\xf0\x85\xf6\x79", "xxxxx") ||
            success == NONE || rel_target(im, guard + 6, (int8_t)b[guard + 5]) != success ||
            !at(im, guard + 6, x64 ? "\0\xf6\xc6\x20" : "\xf6\xc3\x20",
                x64 ? "?xxx" : "xxx"))
            continue;
        DWORD j = guard + (x64 ? 10 : 9);
        unsigned len = (b[j] == 0x75 || (b[j] == 0x90 && b[j + 2] != 0x90)) ? 2 : 6;
        if (!flag_branch(im, j, len))
            continue;
        DWORD zero = j + len;
        unsigned move = x64 && b[zero] == 0x41 ? 3 : 2;
        if (x64) {
            BOOL zero_r9 = at(im, fcall + 5, "\x45\x33\xc9", "xxx") &&
                           at(im, zero, "\x41\x8b\xd9", "xxx");
            BOOL zero_r8 = at(im, fcall + 5, "\x45\x33\xc0", "xxx") &&
                           at(im, zero, "\x41\x8b\xd8", "xxx");
            BOOL zero_edx = at(im, fcall + 5, "\x33\xd2", "xx") &&
                            at(im, zero, "\x8b\xda", "xx");
            if ((!zero_r9 && !zero_r8 && !zero_edx) ||
                (b[guard + 6] != 0x40 && b[guard + 6] != 0x41))
                continue;
        }
        if ((!x64 && !at(im, zero, "\x33\xf6", "xx")) ||
            (x64 && !at(im, zero + move - 2, "\x8b\0", "x?")) ||
            b[zero + move] != 0xeb ||
            rel_target(im, zero + move + 2, (int8_t)b[zero + move + 1]) != success)
            continue;
        *hash = target;
        *filter = ftarget;
        *branch = j;
        *length = len;
        ++count;
    }
    return count == 1;
}

static BOOL plan_boot_options(const Image *im, Plan *plan)
{
    unsigned count = 0;
    for (DWORD o = 0; o + 52 < im->size; ++o) {
        if (!at(im, o, "\xba\x48\x00\x00\x16", "xxxxx"))
            continue;
        DWORD patch;
        const char *new_bytes;
        unsigned length;
        if (im->x64 &&
            at(im, o + 5, "\x48\x8b\xcd\xe8\0\0\0\0\x0f\xb6\x4c\x24\x40\x85\xc0", "xxxx????xxxxxxx") &&
            at(im, o + 24, "\x88\x4c\x24\x40\x88\x0e", "xxxxxx") &&
            at(im, o + 40, "\xba\x49\x00\x00\x16", "xxxxx")) {
            patch = o + 20;
            length = 4;
            new_bytes = "\xb1\x01\x90\x90";
            if (!at(im, patch, "\x41\x0f\x48\xce", "xxxx") &&
                !at(im, patch, new_bytes, "xxxx"))
                continue;
        } else if (!im->x64 &&
                   at(im, o + 5, "\x50\x8b\xcf\xe8\0\0\0\0\x85\xc0", "xxxx????xx") &&
                   at(im, o + 23, "\x88\x45\xff\x88\x06\x8b\x75\x08", "xxxxxxxx") &&
                   at(im, o + 38, "\xba\x49\x00\x00\x16", "xxxxx")) {
            patch = o + 15;
            length = 8;
            new_bytes = "\xb0\x01\x90\x90\x90\x90\x90\x90";
            if (!at(im, patch, "\x0f\x98\xc0\xfe\xc8\x22\x45\xff", "xxxxxxxx") &&
                !at(im, patch, new_bytes, "xxxxxxxx"))
                continue;
        } else {
            continue;
        }
        if (!record(im, plan, patch, new_bytes, length, L"loader integrity option"))
            return FALSE;
        ++count;
    }
    return count == 1;
}

static BOOL plan_secondary(const Image *im, Plan *plan, DWORD hash, DWORD filter)
{
    const BYTE *b = im->bytes;
    for (DWORD o = 0; o + 100 < im->size; ++o) {
        if (b[o] != 0xe8 || !code_span(im, o, 100))
            continue;
        DWORD callee = rel_target(im, o + 5, (int32_t)u32(b + o + 1));
        if (callee == filter) {
            DWORD r = o + 5;
            if (im->x64 && b[r] == 0x45 && b[r + 1] == 0x33)
                r += 3;
            const char *tested = im->x64 ? "\x8b\xd8\x85\xc0\x79" : "\x8b\xd8\x85\xdb\x79";
            if (at(im, r, tested, "xxxxx")) {
                DWORD test = r + 6;
                BOOL reg = im->x64 && at(im, test, "\x41\xf6\0\x20", "xx?x") &&
                           (b[test + 2] == 0xc6 || b[test + 2] == 0xc7);
                BOOL stack = !im->x64 && at(im, test, "\xf6\x45\0\x20", "xx?x");
                if (reg || stack) {
                    DWORD branch = test + 4;
                    unsigned len = b[branch] == 0x75 ||
                                   (b[branch] == 0x90 && b[branch + 2] != 0x90) ? 2 : 6;
                    DWORD fallthrough = branch + len;
                    if (rel_target(im, r + 6, (int8_t)b[r + 5]) == fallthrough &&
                        flag_branch(im, branch, len) &&
                        !record(im, plan, branch, "\x90\x90\x90\x90\x90\x90", len,
                                L"catalog status gate"))
                        return FALSE;
                }
            }
            if (im->x64 && o >= 11 &&
                at(im, o - 11, "\x41\xb8\x30\x00\x08\x00\x8b\xd3\x48\x8b\xcf", "xxxxxxxxxxx") &&
                (at(im, r, "\x8b\xd8", "xx") || at(im, r, "\x31\xdb", "xx")) &&
                !record(im, plan, r, "\x31\xdb", 2, L"boot application status"))
                return FALSE;
            if (!im->x64 && o >= 12 &&
                at(im, o - 12, "\x68\x30\x00\x08\x00\x8b\xd6\xb9", "xxxxxxxx") &&
                (at(im, r, "\x8b\xf0\x5f\x8b\xc6", "xxxxx") ||
                 at(im, r, "\x33\xf6\x5f\x8b\xc6", "xxxxx")) &&
                !record(im, plan, r, "\x33\xf6", 2, L"boot application status"))
                return FALSE;
        }
        if (callee != hash)
            continue;
        /* The alternate catalog path reports the saved status after cleanup.
           Preserve flags and the cleanup branch while clearing that saved status. */
        DWORD r = o + 5;
        BYTE mov = b[r + 1];
        if (!at(im, r + 4, "\x0f\x88\0\0\0\0\x80", "xx????x") ||
            (!im->x64 && !(mov == 0xd8 || mov == 0xf0)) ||
            (im->x64 && mov != 0xf8) || b[r] != 0x8b)
            continue;
        if ((!im->x64 && !(b[r + 2] == 0x85 && b[r + 3] == (mov == 0xd8 ? 0xdb : 0xf6))) ||
            (im->x64 && !at(im, r + 2, "\x85\xc0", "xx")))
            continue;
        DWORD dest = rel_target(im, r + 10, (int32_t)u32(b + r + 6));
        if (dest == NONE || dest <= r || !code_span(im, dest, 32))
            continue;
        BYTE ret_reg = mov == 0xd8 ? 0xc3 : mov == 0xf0 ? 0xc6 : 0xc7;
        BOOL returns_status = FALSE;
        for (DWORD n = dest; n < dest + 30; ++n)
            if (b[n] == 0x8b && b[n + 1] == ret_reg)
                returns_status = TRUE;
        if (returns_status) {
            char zero_status[] = {0x33, (char)(mov == 0xd8 ? 0xdb : mov == 0xf0 ? 0xf6 : 0xff), (char)0x85, (char)0xc0};
            if (!record(im, plan, r, zero_status, sizeof zero_status, L"alternate image status"))
                return FALSE;
        }
    }
    return TRUE;
}

static BOOL plan_revocation(const Image *im, Plan *plan)
{
    const BYTE *b = im->bytes;
    unsigned found = 0;
    for (DWORD o = 0; o + 33 < im->size; ++o) {
        if (b[o] != 0x85 || b[o + 1] != 0xc0 || b[o + 2] != 0x74)
            continue;
        /* This initializer already has a zero-result exit for absent data.
           Leave the special type-8 path intact. */
        if (!at(im, o + 4, "\x83\xf8\x08\x74\x07", "xxxxx") ||
            !(b[o + 9] >= 0xb8 && b[o + 9] <= 0xbf) ||
            !(u32(b + o + 10) == 0xc0000603u || u32(b + o + 10) == 0) ||
            b[o + 14] != 0xeb ||
            rel_target(im, o + 4, (int8_t)b[o + 3]) == NONE ||
            rel_target(im, o + 4, (int8_t)b[o + 3]) != rel_target(im, o + 16, (int8_t)b[o + 15]) ||
            !code_span(im, o, 16))
            continue;
        if (!record(im, plan, o + 10, "\0\0\0\0", 4, L"parsed revocation list status (0603)"))
            return FALSE;
        if (++found > 1)
            return FALSE;
    }
    return TRUE;
}

static BOOL plan_file_revocation(const Image *im, Plan *plan)
{
    unsigned count = 0;
    for (DWORD o = 0; o + 32 < im->size; ++o) {
        DWORD patch;
        const char *replacement;
        if (im->x64 &&
            at(im, o, "\x8b\xd3\x48\x8b\xcf\xe8\0\0\0\0\x84\xc0", "xxxxxx????xx") &&
            (at(im, o + 12, "\x75\x04", "xx") || all_nops(im->bytes + o + 12, 2)) &&
            at(im, o + 14, "\x33\xc0\xeb\x05\xb8\x03\x06\x00\xc0\x48\x8b\x5c\x24", "xxxxxxxxxxxxx")) {
            patch = o + 12;
            replacement = "\x90\x90";
        } else if (!im->x64 &&
                   at(im, o, "\x83\x7d\x08\x10\x72\x12\x6a\x00\xe8\0\0\0\0\x85\xc0", "xxxxxxxxx????xx") &&
                   (at(im, o + 15, "\x74\x07", "xx") || at(im, o + 15, "\xeb\x07", "xx")) &&
                   at(im, o + 17, "\xb8\x03\x06\x00\xc0\xeb\x02\x33\xc0\x5d\xc2\x04\x00", "xxxxxxxxxxxxx")) {
            patch = o + 15;
            replacement = "\xeb\x07";
        } else {
            continue;
        }
        if (!code_span(im, o, 30) ||
            !record(im, plan, patch, replacement, 2, L"file revocation result (0603)") ||
            ++count > 1)
            return FALSE;
    }
    return TRUE;
}

static BOOL plan_boot(const Image *im, Plan *plan, BOOL loader)
{
    static const char oid[] = "1.3.6.1.4.1.311.61.4.1";
    DWORD where = unique_data(im, oid, sizeof oid);
    DWORD hash, filter, branch;
    unsigned length;
    if (where == NONE || !find_main_hash(im, translate(im, where, TRUE, FALSE),
                                       &hash, &filter, &branch, &length)) {
        fwprintf(stderr, L"  Could not uniquely match the image hash caller.\n");
        return FALSE;
    }
    if (!record(im, plan, branch, "\x90\x90\x90\x90\x90\x90", length, L"image hash status gate") ||
        !plan_secondary(im, plan, hash, filter) || !plan_revocation(im, plan) ||
        !plan_file_revocation(im, plan))
        return FALSE;
    if (loader && !plan_boot_options(im, plan)) {
        fwprintf(stderr, L"  Could not uniquely match the boot options routine.\n");
        return FALSE;
    }
    return TRUE;
}

/* The hypervisor loader can continue parsing the image descriptor after a
   failed microcode load. Keep the original failure and skip both reads of
   the invalid descriptor. Both edits must be present or applicable. */
static BOOL plan_hvloader(const Image *im, Plan *plan)
{
    static const wchar_t amd_microcode[] = L"mcupdate_AuthenticAMD.dll";
    static const char original_inner[] =
        "\x48\x8b\x1b\x4c\x8d\x84\x24\xa0\0\0\0\x83\xa4\x24\xa0\0\0\0\0"
        "\x4c\x8b\xcf\x83\xa4\x24\xa4\0\0\0\0\x48\x8b\xe8";
    static const char patched_inner[] =
        "\x48\x8b\xe8\x48\x85\xc0\x75\0\x48\x8b\x1b\x4c\x8d\x84\x24\xa0\0\0\0"
        "\x49\x83\x20\0\x4c\x8b\xcf\x90\x90\x90\x90\x90\x90\x90";
    static const char inner_mask[] = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    static const char patched_mask[] = "xxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxx";
    static const char old_outer[] =
        "\x48\x8b\xd8\x48\x8b\x45\x77\x4c\x8b\x40\x30\x4c\x89\x05\0\0\0\0"
        "\x48\x85\xdb\x74\0\x48\x8b\x57\x10\x48\x8d\x0d\0\0\0\0\xff\x56\x78\xeb\0";
    static const char new_outer[] =
        "\x48\x8b\xd8\x48\x85\xdb\x74\x10\x48\x8b\x57\x10\x48\x8d\x0d\0\0\0\0"
        "\xff\x56\x78\xeb\0\x48\x8b\x45\x77\x4c\x8b\x40\x30\x4c\x89\x05\0\0\0\0";
    static const char old_outer_mask[] = "xxxxxxxxxxxxxx????xxxx?xxxxxxx????xxxx?";
    static const char new_outer_mask[] = "xxxxxxxxxxxxxxx????xxxx?xxxxxxxxxxx????";
    static const char pdb[] = "hvloader.pdb";
    if (!im->x64 || unique_data(im, pdb, sizeof pdb) == NONE ||
        unique_data(im, amd_microcode, sizeof amd_microcode) == NONE)
        return FALSE;

    const BYTE *b = im->bytes;
    unsigned hits = 0;
    for (DWORD o = 5; o + 82 < im->size; ++o) {
        BOOL already = at(im, o, new_outer, new_outer_mask);
        if ((!already && !at(im, o, old_outer, old_outer_mask)) || b[o - 5] != 0xe8 ||
            !code_span(im, o - 5, 55) ||
            !at(im, o + 39, "\x45\x33\xc9\x4c\x89\x45\x0f", "xxxxxxx") ||
            !at(im, o + 73, "\x48\x85\xdb\x74", "xxxx"))
            continue;
        DWORD handler = rel_target(im, o + (already ? 24 : 39), (int8_t)b[o + (already ? 23 : 38)]);
        if (handler != o + 73 || (!already && rel_target(im, o + 23, (int8_t)b[o + 22]) != o + 39))
            continue;
        DWORD inner = rel_target(im, o, (int32_t)u32(b + o - 4));
        if (inner == NONE || !unwind_entry(im, inner) || !code_span(im, inner, 239))
            continue;
        DWORD p = inner + 106;
        if (b[p - 5] != 0xe8 || rel_target(im, p, (int32_t)u32(b + p - 4)) == NONE ||
            !at(im, p + 33, "\x8b\x53\x40\x48\x8b\x4b\x30\xe8", "xxxxxxxx") ||
            !at(im, p + 104, "\x4c\x8d\x5c\x24\x60\x48\x8b\xc5", "xxxxxxxx") ||
            (already ? !at(im, p, patched_inner, patched_mask) || b[p + 7] != 96 :
                       !at(im, p, original_inner, inner_mask)))
            continue;
        char inner_code[sizeof patched_inner], outer_code[sizeof new_outer];
        memcpy(inner_code, patched_inner, sizeof inner_code);
        inner_code[7] = 96; /* original epilogue at p + 104 */
        memcpy(outer_code, new_outer, sizeof outer_code);
        outer_code[23] = 49; /* original failure cleanup at o + 73 */
        uint32_t report = u32(b + o + (already ? 15 : 30)) + (already ? 0 : 15);
        uint32_t global = u32(b + o + (already ? 35 : 14)) - (already ? 0 : 21);
        memcpy(outer_code + 15, &report, sizeof report);
        memcpy(outer_code + 35, &global, sizeof global);
        if (++hits > 1 ||
            !record(im, plan, p, inner_code, sizeof inner_code - 1, L"hypervisor microcode load error") ||
            !record(im, plan, o, outer_code, sizeof outer_code - 1, L"hypervisor microcode error cleanup"))
            return FALSE;
    }
    return hits == 1;
}

static BOOL plan_umci(const Image *im, Plan *plan)
{
    const BYTE *b = im->bytes;
    unsigned matches = 0;
    for (DWORD o = 8; o + 80 < im->size; ++o) {
        DWORD branch;
        const char *replacement;
        if (im->x64 && at(im, o, "\x8b\x05\0\0\0\0\xa8\x01", "xx????xx") &&
            (at(im, o + 8, "\x74\x17", "xx") || all_nops(b + o + 8, 2)) &&
            at(im, o + 10, "\x41\xc6\x07\x01\x48\x8d\x1d", "xxxxxxx") &&
            at(im, o + 33, "\xf6\x45\0\x10\x75", "xx?xx")) {
            branch = o + 8;
            replacement = "\x90\x90";
        } else if (im->x64 && at(im, o, "\x8b\x05\0\0\0\0\xa8\x01\0\x33\x8b\x7d\0\x40\xf6\xc7\x10\x75",
                                    "xx????xx?xxx?xxxxx") &&
                   (b[o + 8] == 0x75 || b[o + 8] == 0xeb) &&
                   at(im, o + 72, "\x41\xc6\x04\x24\x01", "xxxxx")) {
            branch = o + 8;
            replacement = "\xeb\x33";
        } else if (!im->x64 && at(im, o, "\xf6\x05\0\0\0\0\x01\0\x30\xf6\x45\x08\x10\x75",
                                     "xx????x?xxxxxx") &&
                   (b[o + 7] == 0x75 || b[o + 7] == 0xeb) &&
                   at(im, o + 60, "\x8b\x4d\x24\xbf\0\0\0\0\x8b\x55\x28\xc6\x01\x01", "xxxx????xxxxxx")) {
            branch = o + 7;
            replacement = "\xeb\x30";
        } else {
            continue;
        }
        if (!code_span(im, o, 80) ||
            !record(im, plan, branch, replacement, 2, L"CI preview policy fallback") ||
            ++matches > 1)
            return FALSE;
    }
    return TRUE;
}

static BOOL plan_ci(const Image *im, Plan *plan)
{
    const BYTE *b = im->bytes;
    unsigned sites = 0;
    for (DWORD p = 24; p + 13 < im->size; ++p) {
        if (b[p] < 0xb8 || b[p] > 0xbf || u32(b + p + 1) != 0xc0000605u ||
            !code_span(im, p, 5))
            continue;
        DWORD branch = NONE;
        if (im->x64 && at(im, p - 6, "\x49\x3b\x45\x08\0\x0a", "xxxx?x") &&
            (b[p - 2] == 0x7e || b[p - 2] == 0xeb) && b[p + 5] == 0xe9) {
            branch = p - 2;
        } else if (im->x64) {
            for (unsigned back = 2; back <= 21; ++back) {
                DWORD o = p - back;
                if ((b[o] != 0x74 && b[o] != 0xeb) || b[o + 1] > 0x30 ||
                    o + 2 + b[o + 1] <= p + 4)
                    continue;
                BOOL flags = at(im, o + 2, "\x81\xce\x00\x00\x60\x00", "xxxxxx") ||
                             at(im, o + 2, "\x41\x81\xce\x00\x00\x60\x00", "xxxxxxx") ||
                             at(im, o + 2, "\x0f\xba\xee\x16", "xxxx") ||
                             at(im, o + 2, "\x41\x0f\xba\xee\x16", "xxxxx");
                if (flags) {
                    if (branch != NONE)
                        return FALSE;
                    branch = o;
                }
            }
        } else if (at(im, p - 5, "\x3b\x46\x08\0\x0a", "xxx?x") &&
                   (b[p - 2] == 0x76 || b[p - 2] == 0xeb) && b[p + 5] == 0xe9) {
            branch = p - 2;
        } else if (at(im, p - 13, "\x84\xc0\0\x13\x81\xcf\x00\x00\x60\x00\x89\x7d\0",
                      "xx?xxxxxxxxx?") && (b[p - 11] == 0x74 || b[p - 11] == 0xeb) && b[p + 5] == 0xe9) {
            branch = p - 11;
        }
        if (branch == NONE || rel_target(im, branch + 2, (int8_t)b[branch + 1]) == NONE ||
            !record(im, plan, branch, "\xeb", 1, L"CI certificate date branch"))
            return FALSE;
        ++sites;
    }
    return sites > 0 && plan_umci(im, plan);
}

static BOOL has_expiration_ref(const Image *im, DWORD fn, DWORD policy)
{
    if (fn == NONE || !code_span(im, fn, 192) || (im->x64 && !unwind_entry(im, fn)))
        return FALSE;
    for (DWORD o = fn; o < fn + 185; ++o)
        if (references(im, o, policy, TRUE))
            return TRUE;
    return FALSE;
}

static BOOL plan_kernel(const Image *im, Plan *plan)
{
    static const wchar_t name[] = L"Kernel-ExpirationDate";
    DWORD literal = unique_data(im, name, sizeof name);
    if (literal == NONE)
        return FALSE;
    DWORD policy = translate(im, literal, TRUE, FALSE);
    const BYTE *b = im->bytes;
    unsigned stores = 0;
    DWORD query = NONE;
    for (DWORD o = 64; o + 28 < im->size; ++o) {
        BOOL store = im->x64 ? at(im, o, "\x48\xa3\xc8\x02\x00\x00\x80\xf7\xff\xff", "xxxxxxxxxx") :
                     at(im, o, "\x89\x0d\xc8\x02\xdf\xff", "xxxxxx") ||
                     at(im, o, "\xa3\xc8\x02\xdf\xff", "xxxxx");
        if (!store || !code_span(im, o, 10))
            continue;
        if (!im->x64 && !at(im, o + (b[o] == 0x89 ? 11 : 10), "\xa3\xcc\x02\xdf\xff", "xxxxx"))
            return FALSE;
        unsigned hits = 0;
        for (DWORD call = o - 43; call + 5 < o; ++call) {
            const char *patched = im->x64 ? "\x31\xc0\x48\x89\x01" : "\xb8\x34\x00\x00\xc0";
            BOOL existing = at(im, call, patched, "xxxxx");
            if ((!existing && b[call] != 0xe8) ||
                (im->x64 && !(at(im, call - 7, "\x48\x8d\x0d", "xxx") ||
                              at(im, call - 10, "\x48\x8d\x0d", "xxx"))) ||
                (!im->x64 && b[call - 5] != 0xb9))
                continue;
            if (!existing) {
                DWORD dest = rel_target(im, call + 5, (int32_t)u32(b + call + 1));
                if (!has_expiration_ref(im, dest, policy))
                    continue;
                if (query != NONE && query != dest)
                    return FALSE;
                query = dest;
            }
            if (!im->x64) {
                DWORD js = call + 7;
                if (at(im, call + 5, "\x8b\xd0\x33\xdb\x85\xd2", "xxxxxx"))
                    js = call + 11;
                else if (!at(im, call + 5, "\x85\xc0", "xx"))
                    continue;
                if (!at(im, js, "\x0f\x88", "xx"))
                    continue;
                DWORD dest = rel_target(im, js + 6, (int32_t)u32(b + js + 2));
                DWORD global = u32(b + call - 4);
                if (dest == NONE || !code_span(im, dest, 20) ||
                    !at(im, dest + 2, "\x89\x1d", "xx") || u32(b + dest + 4) != global + 4 ||
                    !((at(im, dest, "\x8b\xcb", "xx") && at(im, dest + 8, "\x89\x0d", "xx") &&
                       u32(b + dest + 10) == global) ||
                      (at(im, dest, "\x8b\xc3", "xx") && b[dest + 8] == 0xa3 &&
                       u32(b + dest + 9) == global)))
                    continue;
            }
            if (!record(im, plan, call, patched, 5, L"kernel expiration query"))
                return FALSE;
            ++hits;
        }
        if (hits != 1)
            return FALSE;
        ++stores;
    }
    return stores == 2;
}
