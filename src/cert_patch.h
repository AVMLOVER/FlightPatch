/* Certificate expiry bypass for wintrust.dll and crypt32.dll.

   Expired preview signing certificates are rejected by the Authenticode trust
   path: the chain policy maps a time-invalid chain to CERT_E_EXPIRED, and the
   wintrust signature checker records a positive "time valid" bit only when
   crypt32 reports the certificate inside its validity period.

   The matching is intentionally build-agnostic:

   - crypt32.dll is anchored by export name, which is stable across builds, and
     each routine is replaced at its entry, so no offset is assumed.
   - wintrust.dll is anchored by the delay-import slot of those two crypt32
     routines, then the branch that guards the status bit is found by scanning
     forward for "test reg,reg / conditional jump / bit-set [mem], imm". Register
     allocation, NOP padding and the bts/or/set encodings are all accepted.
   - The chain-policy expiry assignment is found by the CERT_E_EXPIRED constant
     followed by a jump, with the branch that skips it located relative to the
     assignment rather than by a fixed byte string.

   Revocation, untrusted-root and signature-mismatch results are untouched. */

/* The instruction that records a positive status bit: bts [mem], imm8,
   or dword ptr [mem], imm32, or the 8-bit forms. Returns its length. */
static unsigned cert_bit_set(const Image *im, DWORD offset, BYTE bit)
{
    if (offset + 2 > im->size)
        return 0;
    const BYTE *p = im->bytes + offset;
    if (p[0] == 0x0f && p[1] == 0xba && offset + 4 <= im->size &&
        ((p[2] >> 3) & 7) == 5 && p[3] == bit)
        return 4;
    if (p[0] == 0x81 && offset + 6 <= im->size && ((p[1] >> 3) & 7) == 1 &&
        u32(p + 2) == 1u << (bit & 31))
        return 6;
    if (p[0] == 0x83 && offset + 4 <= im->size && ((p[1] >> 3) & 7) == 1 &&
        p[3] == (BYTE)(1u << (bit & 7)))
        return 4;
    if (p[0] == 0x80 && offset + 3 <= im->size && ((p[1] >> 3) & 7) == 1 &&
        p[2] == (BYTE)(1u << (bit & 7)))
        return 3;
    return 0;
}

/* A two-byte test of one register with itself: test r32,r32. */
static BOOL cert_test_self(const Image *im, DWORD offset)
{
    if (offset + 2 > im->size)
        return FALSE;
    BYTE opcode = im->bytes[offset], modrm = im->bytes[offset + 1];
    return (opcode == 0x85 || opcode == 0x84) && (modrm & 0xc0) == 0xc0;
}

/* Find the branch that keeps a positive status bit from being set, starting at
   the instruction after a call to one of the crypt32 helpers. The branch skips
   the bit-set instruction when the helper reported a failure, so making it
   unconditional records the bit in both cases. Returns the branch opcode offset
   or NONE. */
static DWORD cert_status_branch(const Image *im, DWORD start, DWORD limit, BYTE bit, BOOL *already)
{
    *already = FALSE;
    DWORD patched = NONE;
    for (DWORD o = start; o + 6 <= limit && o + 6 <= im->size; ++o) {
        if (!cert_test_self(im, o))
            continue;
        DWORD body = o + 2;
        BYTE branch = im->bytes[body];
        /* Already patched: test reg,reg; nop; nop; bit-set. */
        if (branch == 0x90 && im->bytes[body + 1] == 0x90 && cert_bit_set(im, body + 2, bit)) {
            if (patched != NONE)
                return NONE; /* ambiguous */
            patched = body;
            continue;
        }
        if (branch < 0x70 || branch > 0x7f)
            continue;
        BYTE distance = im->bytes[body + 1];
        unsigned length = cert_bit_set(im, body + 2, bit);
        if (!length || distance != length || !code_span(im, body, 2 + length))
            continue;
        if (patched != NONE)
            return NONE; /* ambiguous */
        patched = body;
    }
    if (patched == NONE)
        return NONE;
    *already = im->bytes[patched] == 0x90;
    return patched;
}

static BOOL plan_wintrust(const Image *im, Plan *plan)
{
    static const struct { const char *name; BYTE bit; const wchar_t *label; } checks[] = {
        {"CertVerifyTimeValidity", 24, L"certificate time validity"},
        {"CertVerifyValidityNesting", 20, L"certificate validity nesting"}
    };
    if (im->machine == IMAGE_FILE_MACHINE_ARM64) {
        fwprintf(stderr, L"  ARM64 images are not supported by this rule set.\n");
        return FALSE;
    }
    unsigned applied = 0;
    for (unsigned i = 0; i < ARRAYSIZE(checks); ++i) {
        DWORD slot = pe_import_slot(im, "crypt32.dll", checks[i].name);
        if (slot == NONE) {
            fwprintf(stderr, L"  %hs is not imported from crypt32.dll.\n", checks[i].name);
            return FALSE;
        }
        DWORD sites[8];
        unsigned count = pe_call_sites(im, slot, sites);
        if (count != 1) {
            fwprintf(stderr, L"  %hs has %u call sites; one is required.\n", checks[i].name, count);
            return FALSE;
        }
        BOOL already = FALSE;
        DWORD branch = cert_status_branch(im, sites[0] + 6, sites[0] + 6 + 32, checks[i].bit, &already);
        if (branch == NONE) {
            fwprintf(stderr, L"  The status bit after %hs is not recognized in this build.\n", checks[i].name);
            return FALSE;
        }
        if (!record(im, plan, branch, "\x90\x90", 2, checks[i].label))
            return FALSE;
        ++applied;
    }
    return applied == ARRAYSIZE(checks);
}

/* The chain policy assigns CERT_E_EXPIRED when the signer certificate is outside
   its period. Locate the assignment, then the branch that skips it, and take that
   branch unconditionally. Absent or ambiguous layouts leave the policy alone. */
static DWORD cert_expired_branch(const Image *im, BOOL *already)
{
    *already = FALSE;
    DWORD found = NONE;
    /* The assignment may be "mov reg, imm32" (one opcode byte before the
       immediate), "mov [mem], imm32" with a disp8 (three bytes) or with a disp32
       (six bytes). The branch sits right before the assignment and lands after
       the assignment and its jump, which is where the accepted path continues. */
    static const DWORD prefixes[] = {1, 3, 6};
    for (DWORD o = 0; o + 6 <= im->size; ++o) {
        if (u32(im->bytes + o) != 0x800b0101u || !code_span(im, o, 4))
            continue;
        for (unsigned k = 0; k < ARRAYSIZE(prefixes); ++k) {
            DWORD start = o - prefixes[k];
            if (start < 2)
                continue;
            DWORD at = start - 2;
            BYTE opcode = im->bytes[at];
            BOOL jump = opcode >= 0x70 && opcode <= 0x7f;
            if (!jump && opcode != 0xeb)
                continue;
            BYTE distance = im->bytes[at + 1];
            DWORD target = at + 2 + distance;
            if (target < o + 4 || target > o + 12 || !code_span(im, at, 2))
                continue;
            if (found != NONE && found != at)
                return NONE;
            found = at;
            *already = opcode == 0xeb;
        }
    }
    return found;
}

static BOOL plan_crypt32(const Image *im, Plan *plan)
{
    if (im->machine == IMAGE_FILE_MACHINE_ARM64) {
        fwprintf(stderr, L"  ARM64 images are not supported by this rule set.\n");
        return FALSE;
    }
    DWORD validity = pe_export(im, "CertVerifyTimeValidity");
    DWORD nesting = pe_export(im, "CertVerifyValidityNesting");
    if (validity == NONE || nesting == NONE || validity == nesting ||
        !code_span(im, validity, 6) || !code_span(im, nesting, 6)) {
        fwprintf(stderr, L"  The two certificate helpers are not both exported by name.\n");
        return FALSE;
    }
    /* Both exports compare one FILETIME range and report validity (0) or an
       accepted nesting (1). Return that result without the comparison. */
    if (!record(im, plan, validity, "\x33\xc0\xc3", 3, L"certificate time validity") ||
        !record(im, plan, nesting, "\xb8\x01\x00\x00\x00\xc3", 6, L"certificate validity nesting"))
        return FALSE;

    BOOL already = FALSE;
    DWORD branch = cert_expired_branch(im, &already);
    if (branch == NONE) {
        wprintf(L"  The chain-policy expiry branch was not recognized; the two helpers still apply.\n");
        return TRUE;
    }
    if (!record(im, plan, branch, "\xeb", 1, L"chain policy expiry result"))
        return FALSE;
    return TRUE;
}

static BOOL plan_cert_any(const Image *im, Plan *plan)
{
    return plan_alternate(im, plan, plan_wintrust, plan_crypt32);
}

enum { CERT_WINTRUST, CERT_CRYPT32 };
