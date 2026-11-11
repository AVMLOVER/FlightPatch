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

typedef struct {
    DWORD branch, end, lookup;
} CiBootOptionLoop;

static BOOL ci_boot_option_loop(const Image *im, DWORD start, DWORD option, unsigned reg,
                                BOOL allow_patched, CiBootOptionLoop *loop)
{
    /* RAX receives the lookup result, EDX holds the option, and RSP is the stack. */
    if (reg == 0 || reg == 2 || reg == 4 || !code_span(im, start, 24)) return FALSE;
    const BYTE *p = im->bytes + start;
    BOOL copy = (p[5] == (0x48 | (reg >> 3)) && p[6] == 0x8b && p[7] == (0xc8 | (reg & 7))) ||
                (p[5] == (0x48 | ((reg >> 3) << 2)) && p[6] == 0x89 && p[7] == (0xc1 | ((reg & 7) << 3)));
    if (p[0] != 0xba || u32(p + 1) != option || !copy ||
        !at(im, start + 8, "\xe8\0\0\0\0\x48\x85\xc0", "x????xxx") ||
        (p[16] != 0x74 && !(allow_patched && p[16] == 0xeb)) ||
        !at(im, start + 18, "\xc6\x40\x14\x01", "xxxx")) return FALSE;
    DWORD length = p[22] == 0xeb ? 24 : 27;
    if (length == 27 && (p[22] != 0xe9 || !code_span(im, start, length))) return FALSE;
    int32_t back = length == 24 ? (int8_t)p[23] : (int32_t)u32(p + 23);
    DWORD lookup = rel_target(im, start + 13, (int32_t)u32(p + 9));
    if (18 + (int8_t)p[17] != (int)length || (int64_t)length + back != 0 || lookup == NONE) return FALSE;
    *loop = (CiBootOptionLoop){start + 16, start + length, lookup};
    return TRUE;
}

/* Resolve the two loops by their option IDs, shared list, and call and branch
   targets. Preserve the first option by taking its existing exit branch. */
static DWORD ci_boot_invalidation_loop(const Image *im, DWORD offset)
{
    if (!code_span(im, offset, 11)) return NONE;
    const BYTE *p = im->bytes + offset;
    if ((p[0] & 0xfb) != 0x48 || p[1] != 0x8b || (p[2] & 0xc7) != 5) return NONE;
    unsigned reg = ((p[2] >> 3) & 7) | ((p[0] & 4) << 1);
    /* The application entry is spilled to the stack before the option loops.
       The UEFI loader spills RBX and the legacy loader spills R12, so accept
       any REX.W store through RBP. */
    const BYTE *spill = p + 7;
    BOOL initialize = (spill[0] & 0xf8) == 0x48 && spill[1] == 0x89 && (spill[2] & 0xc7) == 0x45;
    CiBootOptionLoop first, second;
    if (!ci_boot_option_loop(im, offset + (initialize ? 11 : 7), 0x16000048, reg, TRUE, &first) ||
        !code_span(im, first.end, 7)) return NONE;
    const BYTE *next = im->bytes + first.end;
    if ((next[0] & 0xfb) != 0x48 || next[1] != 0x8b || (next[2] & 0xc7) != 5)
        return NONE;
    unsigned next_reg = ((next[2] >> 3) & 7) | ((next[0] & 4) << 1);
    if (!ci_boot_option_loop(im, first.end + 7, 0x260000e1, next_reg, FALSE, &second) ||
        first.lookup != second.lookup || !code_span(im, second.end, 23) ||
        !at(im, second.end, "\x48\x8b\x0d\0\0\0\0\x4c\x8d\x45\0\xbf\x30\x00\x00\x12\x8b\xd7\xe8", "xxx????xxx?xxxxxxxx") ||
        (initialize && p[10] != im->bytes[second.end + 10])) return NONE;
    int64_t slot = (int64_t)offset + 7 + (int32_t)u32(p + 3);
    if (slot != (int64_t)first.end + 7 + (int32_t)u32(next + 3) ||
        slot != (int64_t)second.end + 7 + (int32_t)u32(im->bytes + second.end + 3)) return NONE;
    DWORD read = rel_target(im, second.end + 23, (int32_t)u32(im->bytes + second.end + 19));
    DWORD function_start, function_end;
    return read != NONE && read != first.lookup &&
           ci_function_range(im, offset, &function_start, &function_end) && second.end + 23 <= function_end
           ? first.branch : NONE;
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
    BOOL loop = FALSE;
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
        DWORD branch = (bytes[offset] & 0xfb) == 0x48 ? ci_boot_invalidation_loop(im, offset) : NONE;
        if (branch != NONE) {
            if (found != NONE) return FALSE;
            found = branch;
            loop = TRUE;
        }
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
        /* Newer loaders (29704 and later) keep the three option calls but change the
           code between each constant and its call. Walk the group through the three
           RIP-relative context loads of the same slot and the option constants, then
           neutralise the call that removes DisableIntegrityChecks. */
        if (bytes[offset] == 0x48 && bytes[offset + 1] == 0x8b && bytes[offset + 2] == 0x0d &&
            bytes[offset + 7] == 0xba && u32(bytes + offset + 8) == 0x16000048u &&
            code_span(im, offset, 12)) {
            int64_t slot = (int64_t)offset + 7 + (int64_t)(int32_t)u32(bytes + offset + 3);
            DWORD cursor = offset + 12, removal_at = NONE, removal = NONE, reader = NONE;
            for (unsigned group = 0; group < 2; ++group) {
                DWORD load = NONE;
                for (DWORD k = cursor; k + 8 <= cursor + 24 && k + 8 <= im->size; ++k) {
                    if (bytes[k] == 0x48 && bytes[k + 1] == 0x8b && bytes[k + 2] == 0x0d &&
                        slot == (int64_t)(k + 7) + (int64_t)(int32_t)u32(bytes + k + 3)) {
                        load = k;
                        break;
                    }
                }
                if (load == NONE)
                    break;
                DWORD constant = NONE;
                for (DWORD k = load + 7; k + 4 <= load + 24 && k + 4 <= im->size; ++k) {
                    DWORD value = u32(bytes + k);
                    if (value == 0x260000e1u || value == 0x12000030u) {
                        constant = k;
                        break;
                    }
                }
                if (constant == NONE)
                    break;
                DWORD call_at = NONE, target = NONE;
                for (DWORD k = constant + 4; k + 5 <= constant + 24 && k + 5 <= im->size; ++k) {
                    if (bytes[k] != 0xe8)
                        continue;
                    target = rel_target(im, k + 5, (int32_t)u32(bytes + k + 1));
                    if (target != NONE) {
                        call_at = k;
                        break;
                    }
                }
                if (target == NONE)
                    break;
                if (group == 0) {
                    cursor = call_at + 5;   /* the ELAM removal keeps its behaviour */
                    continue;
                }
                reader = target;
                for (DWORD k = offset + 12; k + 5 <= load && k + 5 <= im->size; ++k) {
                    if (bytes[k] != 0xe8)
                        continue;
                    removal = rel_target(im, k + 5, (int32_t)u32(bytes + k + 1));
                    if (removal != NONE) {
                        removal_at = k;
                        break;
                    }
                }
                break;
            }
            if (reader != NONE && removal_at != NONE && removal != NONE && removal != reader &&
                code_span(im, removal_at, 5)) {
                if (found != NONE)
                    return FALSE;
                found = removal_at;
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
    return found != NONE && record(im, plan, found, loop ? "\xeb" : "\x90\x90\x90\x90\x90",
                                   loop ? 1 : 5, L"keep the loader's BCD nointegritychecks option");
}

/* A loader may carry the boot signature gates, the nointegritychecks
   preservation patch, or both. Every matcher that recognizes the file is
   merged into one plan; a loader that neither matcher recognizes is refused. */
/* Merge every plan that recognized the file. A loader carries at most one of
   these rule sets, so an overlap means the structure was misread. */
static BOOL plan_merge(const Image *im, Plan *plan, const Plan *first, BOOL have_first,
                       const Plan *second, BOOL have_second, const Plan *third, BOOL have_third)
{
    const Plan *sources[3] = {first, second, third};
    BOOL present[3] = {have_first, have_second, have_third};
    unsigned merged = 0;
    for (unsigned pass = 0; pass < 3; ++pass) {
        if (!present[pass])
            continue;
        for (unsigned i = 0; i < sources[pass]->count; ++i) {
            const Change *change = &sources[pass]->edits[i];
            if (!record(im, plan, change->at, (const char *)change->bytes, change->length, change->label))
                return FALSE;
            ++merged;
        }
        plan->existing += sources[pass]->existing;
    }
    return merged || plan->existing;
}

/* The only loader patch /cishim applies: keep the explicit BCD nointegritychecks
   option through OslPrepareTarget. Nothing else is touched. A build whose loader
   does not match this structure is refused, because a forced integrity option or
   the older image-hash gates changed BCD handling on newer previews and could
   stop the start with 0xc0000098. /winload-modify still applies the full set for
   a release loader. */
static BOOL plan_loader(const Image *im, Plan *plan)
{
    Plan keep = {0};
    if (!plan_ci_boot(im, &keep) || (!keep.count && !keep.existing))
        return FALSE;
    return plan_merge(im, plan, &keep, TRUE, NULL, FALSE, NULL, FALSE);
}

/* The full loader patch used for a release loader that has to accept a modified
   image: signature gates, revocation gates and the option preservation. */
static BOOL plan_loader_gates(const Image *im, Plan *plan)
{
    Plan gates = {0}, options = {0};
    BOOL have_gates = plan_boot(im, &gates, TRUE);
    BOOL have_options = plan_ci_boot(im, &options);
    if (!have_gates && !have_options)
        return FALSE;
    return plan_merge(im, plan, &gates, have_gates, &options, have_options, NULL, FALSE);
}

/* Run the first matcher that recognizes the file, without keeping any partial
   plan from one that does not. */
static BOOL plan_alternate(const Image *im, Plan *plan, PatchPlan first, PatchPlan second)
{
    Plan scratch = {0};
    if (first(im, &scratch) && (scratch.count || scratch.existing)) {
        *plan = scratch;
        return TRUE;
    }
    memset(&scratch, 0, sizeof scratch);
    if (second(im, &scratch) && (scratch.count || scratch.existing)) {
        *plan = scratch;
        return TRUE;
    }
    return FALSE;
}

static BOOL plan_ci_any(const Image *im, Plan *plan)
{
    return plan_alternate(im, plan, plan_ci_expiry, plan_loader);
}

enum { CI_BINARY, CI_LOADER };

typedef struct {
    const wchar_t *relative;   /* below the selected offline Windows root */
    const wchar_t *leaf;       /* file name inside a folder of extracted files */
    const wchar_t *name;
    unsigned kind;
    BOOL required;
    BOOL skip_unsupported;
} CiTarget;

/* The UEFI loader, the legacy loader and their resume counterparts are separate
   files. winresume mirrors winload so a resumed session keeps the same BCD
   integrity option. System32\Boot holds hard links on deployed images; the
   engine de-duplicates them by file identity. */
static const CiTarget ci_targets[] = {
    {L"Windows\\System32\\ci.dll", L"ci.dll", L"ci.dll", CI_BINARY, TRUE, FALSE},
    {L"Windows\\System32\\winload.efi", L"winload.efi", L"winload.efi", CI_LOADER, FALSE, FALSE},
    {L"Windows\\System32\\winresume.efi", L"winresume.efi", L"winresume.efi", CI_LOADER, FALSE, TRUE},
    {L"Windows\\System32\\winload.exe", L"winload.exe", L"winload.exe", CI_LOADER, FALSE, FALSE},
    {L"Windows\\System32\\winresume.exe", L"winresume.exe", L"winresume.exe", CI_LOADER, FALSE, TRUE},
    {L"Windows\\System32\\Boot\\winload.efi", L"Boot\\winload.efi", L"winload.efi", CI_LOADER, FALSE, FALSE},
    {L"Windows\\System32\\Boot\\winresume.efi", L"Boot\\winresume.efi", L"winresume.efi", CI_LOADER, FALSE, TRUE},
    {L"Windows\\System32\\Boot\\winload.exe", L"Boot\\winload.exe", L"winload.exe", CI_LOADER, FALSE, FALSE},
    {L"Windows\\System32\\Boot\\winresume.exe", L"Boot\\winresume.exe", L"winresume.exe", CI_LOADER, FALSE, TRUE}
};

enum { CI_TARGET_COUNT = sizeof ci_targets / sizeof ci_targets[0] };

static BOOL ci_winload_name(const wchar_t *name)
{
    return !_wcsnicmp(name, L"winload.", 8);
}

/* Preflight: the required CI binary and at least one loader must be present, and
   every loader must share the CI architecture. No file is opened for writing. */
static BOOL ci_preflight(const wchar_t *base, BOOL loader_only, BOOL flat)
{
    wchar_t path[PATH_SIZE];
    WORD machine = 0;
    BOOL any_loader = FALSE;
    for (unsigned i = 0; i < CI_TARGET_COUNT; ++i) {
        if (loader_only && ci_targets[i].kind == CI_BINARY)
            continue;
        const wchar_t *relative = flat ? ci_targets[i].leaf : ci_targets[i].relative;
        if (!build_path(path, base, relative) || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
            continue;
        if (ci_targets[i].kind == CI_LOADER) {
            any_loader |= ci_winload_name(ci_targets[i].name);
            continue;
        }
        machine = spp_pe_machine(path);
    }
    if (!loader_only && !flat && !machine) {
        fwprintf(stderr, L"No readable ci.dll in %ls.\n", base);
        return FALSE;
    }
    if (!any_loader) {
        fwprintf(stderr, L"No Windows loader (winload.efi or winload.exe) found in %ls.\n", base);
        return FALSE;
    }
    if (!machine)
        return TRUE;
    for (unsigned i = 0; i < CI_TARGET_COUNT; ++i) {
        if (ci_targets[i].kind != CI_LOADER)
            continue;
        const wchar_t *relative = flat ? ci_targets[i].leaf : ci_targets[i].relative;
        if (!build_path(path, base, relative) || GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES)
            continue;
        WORD other = spp_pe_machine(path);
        if (other && other != machine) {
            fwprintf(stderr, L"%ls and ci.dll have different target architectures. No files changed.\n", path);
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL patch_ci_command(BCRYPT_ALG_HANDLE algorithm, const wchar_t *argument, BOOL loader_only)
{
    wchar_t path[PATH_SIZE], parent[PATH_SIZE], base[PATH_SIZE];
    InputKind input;
    PatchScope scope;
    if (!normalize(path, argument) || !patch_input_kind(path, &input)) {
        fwprintf(stderr, L"Specify an offline Windows root, a folder of extracted files, or a single file.\n");
        return FALSE;
    }
    base[0] = L'\0';

    PatchSpec specs[CI_TARGET_COUNT];
    unsigned char states[CI_TARGET_COUNT] = {0};
    unsigned count = 0;

    if (input == INPUT_FILE) {
        if (!patch_parent_directory(path, parent) || !patch_scope_init(&scope, parent)) {
            fwprintf(stderr, L"Cannot resolve the folder that contains %ls.\n", path);
            return FALSE;
        }
        specs[count++] = (PatchSpec){.relative = path, .name = patch_leaf(path), .required = TRUE,
                                     .skip_unsupported = FALSE,
                                     .plan = loader_only ? plan_loader : plan_ci_any};
    } else {
        if (!patch_scope_init(&scope, path)) {
            fwprintf(stderr, L"Cannot resolve a safe folder at %ls.\n", path);
            return FALSE;
        }
        wcsncpy(base, path, PATH_SIZE - 1);
        base[PATH_SIZE - 1] = L'\0';
        BOOL flat = input == INPUT_FLAT;
        if (!ci_preflight(base, loader_only, flat))
            return FALSE;
        for (unsigned i = 0; i < CI_TARGET_COUNT; ++i) {
            if (loader_only && ci_targets[i].kind == CI_BINARY)
                continue;
            specs[count++] = (PatchSpec){
                .relative = flat ? ci_targets[i].leaf : ci_targets[i].relative,
                .name = ci_targets[i].name,
                .required = ci_targets[i].required && !loader_only,
                .skip_unsupported = ci_targets[i].skip_unsupported,
                .plan = ci_targets[i].kind == CI_BINARY ? plan_ci_expiry : plan_loader
            };
        }
    }

    BOOL ok = patch_specs(algorithm, &scope, input == INPUT_FILE ? NULL : base, specs, count, states, NULL, NULL);
    if (!ok)
        return FALSE;

    unsigned changed = 0, already = 0;
    for (unsigned i = 0; i < count; ++i) {
        changed += states[i] == SPEC_CHANGED;
        already += states[i] == SPEC_ALREADY;
    }
    if (!changed && !already) {
        fwprintf(stderr, L"No supported file was found for this mode. No files changed.\n");
        return FALSE;
    }
    patch_report(input == INPUT_FILE ? NULL : base, states, count);
    if (!loader_only)
        wprintf(L"The CI build-expiry callback now returns a zero expiry time.\n");
    wprintf(L"The loaders keep an explicit BCD nointegritychecks option.\n"
            L"Before rebooting, set nointegritychecks on for the target Windows BCD entry, with Secure Boot off.\n"
            L"Example: bcdedit /store S:\\EFI\\Microsoft\\Boot\\BCD /set {default} nointegritychecks on\n");
    return TRUE;
}


