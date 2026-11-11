/* /wintrust and /wintrust-approval - patch the certificate-expiry logic in
   wintrust.dll/crypt32.dll and give the result a valid local signature.

   The tested preview builds reject a modified system DLL at load (green screen
   0xc000021a with 0xc0000428), so a byte patch alone cannot work. Both modes
   replace the invalid Microsoft signature with a local one and install the
   matching self-signed certificate as a trusted root and trusted publisher:

   /wintrust           running Windows: stage the signed files under
                       %SystemRoot%\NTTP-WINTRUST-<id>, install the certificate and
                       schedule the replacement for the next start.
   /wintrust-approval  offline image: rewrite and sign the files in place, write
                       the certificate into the offline SOFTWARE hive's Root and
                       TrustedPublisher stores, and keep FILE.bak backups.

   Both keep a journal so the matching restore undoes the files and the trust. */

#define WINTRUST_SUBJECT_NAME L"NT Timebomb Patch local wintrust"
#define WINTRUST_SUBJECT L"CN=" WINTRUST_SUBJECT_NAME
#define WINTRUST_RECEIPT L"SOFTWARE\\NTTimebombPatch\\Wintrust"
#define WINTRUST_STAGE_PREFIX L"NTTP-WINTRUST-"

enum { WINTRUST_ENTRIES = 4, WINTRUST_NAME = 16 };

typedef struct {
    const wchar_t *relative;
    const wchar_t *leaf;
    const wchar_t *name;
    unsigned kind;   /* 0: wintrust.dll, 1: crypt32.dll */
} WintrustTarget;

static const WintrustTarget wintrust_targets[WINTRUST_ENTRIES] = {
    {L"Windows\\System32\\wintrust.dll", L"wintrust.dll", L"wintrust.dll", 0},
    {L"Windows\\System32\\crypt32.dll", L"crypt32.dll", L"crypt32.dll", 1},
    {L"Windows\\SysWOW64\\wintrust.dll", L"SysWOW64\\wintrust.dll", L"wintrust.dll", 0},
    {L"Windows\\SysWOW64\\crypt32.dll", L"SysWOW64\\crypt32.dll", L"crypt32.dll", 1}
};

static PatchPlan wintrust_plan(unsigned kind)
{
    return kind == 0 ? plan_wintrust : plan_crypt32;
}

/* Strip the invalid Microsoft signature before the local one is embedded. */
static BOOL wintrust_build(BCRYPT_ALG_HANDLE algorithm, Output *after, void *context)
{
    (void)algorithm;
    (void)context;
    if (!signer_strip_signature(after->data, &after->size)) {
        fwprintf(stderr, L"Unexpected certificate table layout; the file was not changed.\n");
        return FALSE;
    }
    return TRUE;
}

/* A module this package already signed is left alone; the certificate is read
   back from it for the trust store. */
static BOOL wintrust_recognized(const wchar_t *path, void *context)
{
    (void)context;
    NttpCertificate certificate = {0};
    return signer_extract(path, WINTRUST_SUBJECT_NAME, &certificate);
}

static BOOL wintrust_sha1(const BYTE *data, DWORD size, BYTE digest[20])
{
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_HASH_HANDLE hash;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA1_ALGORITHM, NULL, 0) < 0)
        return FALSE;
    BOOL ok = BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) >= 0 &&
              BCryptHashData(hash, (PUCHAR)data, size, 0) >= 0 &&
              BCryptFinishHash(hash, digest, 20, 0) >= 0;
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static BOOL wintrust_thumbprint(const NttpCertificate *certificate, wchar_t thumb[41])
{
    static const wchar_t digits[] = L"0123456789ABCDEF";
    BYTE digest[20];
    if (!wintrust_sha1(certificate->der, certificate->size, digest))
        return FALSE;
    for (unsigned i = 0; i < sizeof digest; ++i) {
        thumb[i * 2] = digits[digest[i] >> 4];
        thumb[i * 2 + 1] = digits[digest[i] & 15];
    }
    thumb[sizeof digest * 2] = L'\0';
    return TRUE;
}

/* ---- offline certificate stores (SOFTWARE hive of the serviced image) ---- */

typedef struct {
    SlRegistry api;
    SlKey hive;
    wchar_t path[PATH_SIZE];
    wchar_t backup[PATH_SIZE];
    wchar_t temporary[PATH_SIZE];
    BOOL open;
} WintrustHive;

static BOOL wintrust_registry_open(WintrustHive *hive)
{
    memset(hive, 0, sizeof *hive);
    hive->api.module = LoadLibraryW(L"offreg.dll");
    if (!hive->api.module) {
        wchar_t beside[PATH_SIZE];
        UINT length = GetModuleFileNameW(NULL, beside, PATH_SIZE);
        wchar_t *slash = length && length < PATH_SIZE ? wcsrchr(beside, L'\\') : NULL;
#if defined(__aarch64__)
        static const wchar_t name[] = L"offreg-arm64.dll";
#elif defined(_WIN64)
        static const wchar_t name[] = L"offreg-x64.dll";
#else
        static const wchar_t name[] = L"offreg-x86.dll";
#endif
        if (!slash)
            return FALSE;
        wcscpy(slash + 1, L"dependencies\\");
        wcscat(slash + 1, name);
        hive->api.module = LoadLibraryW(beside);
        if (!hive->api.module)
            return FALSE;
    }
#define WINTRUST_IMPORT(field, name) do { \
        FARPROC address = GetProcAddress(hive->api.module, name); \
        memcpy(&hive->api.field, &address, sizeof address); \
        if (!address) return FALSE; \
    } while (0)
    WINTRUST_IMPORT(OpenHive, "OROpenHive");
    WINTRUST_IMPORT(CloseHive, "ORCloseHive");
    WINTRUST_IMPORT(SaveHive, "ORSaveHive");
    WINTRUST_IMPORT(OpenKey, "OROpenKey");
    WINTRUST_IMPORT(CloseKey, "ORCloseKey");
    WINTRUST_IMPORT(CreateKey, "ORCreateKey");
    WINTRUST_IMPORT(SetValue, "ORSetValue");
    WINTRUST_IMPORT(GetValue, "ORGetValue");
    WINTRUST_IMPORT(DeleteKey, "ORDeleteKey");
    WINTRUST_IMPORT(EnumKey, "OREnumKey");
#undef WINTRUST_IMPORT
    return TRUE;
}

static BOOL wintrust_hive_load(WintrustHive *hive, const wchar_t *root)
{
    if (root && !wintrust_registry_open(hive))
        return FALSE;
    if (!build_path(hive->path, root, L"Windows\\System32\\config\\SOFTWARE") ||
        swprintf(hive->backup, PATH_SIZE, L"%ls.nttp-wintrust", hive->path) < 0 ||
        swprintf(hive->temporary, PATH_SIZE, L"%ls.nttp-new", hive->path) < 0)
        return FALSE;
    hive->open = GetFileAttributesW(hive->path) != INVALID_FILE_ATTRIBUTES &&
                 hive->api.OpenHive(hive->path, &hive->hive) == ERROR_SUCCESS;
    return hive->open;
}

static void wintrust_hive_close(WintrustHive *hive)
{
    if (hive->open)
        hive->api.CloseHive(hive->hive);
    hive->open = FALSE;
}

/* The SOFTWARE hive is far larger than a PE image, so it is copied in chunks
   instead of through the image-sized read helper. */
static BOOL wintrust_copy(HANDLE source, HANDLE target)
{
    enum { CHUNK = 1 << 20 };
    BYTE *buffer = malloc(CHUNK);
    LARGE_INTEGER start = {0};
    DWORD read = 0;
    BOOL ok = buffer && SetFilePointerEx(source, start, NULL, FILE_BEGIN) &&
              SetFilePointerEx(target, start, NULL, FILE_BEGIN);
    while (ok && ReadFile(source, buffer, CHUNK, &read, NULL) && read) {
        DWORD written = 0;
        ok = WriteFile(target, buffer, read, &written, NULL) && written == read;
    }
    free(buffer);
    return ok;
}

/* offreg cannot save over the open hive, so the saved copy replaces the file. */
static BOOL wintrust_hive_publish(WintrustHive *hive)
{
    DWORD error = hive->api.SaveHive(hive->hive, hive->temporary, 6, 1);
    wintrust_hive_close(hive);
    if (error) {
        fwprintf(stderr, L"Cannot save the offline SOFTWARE hive (Win32 %lu).\n", error);
        return FALSE;
    }
    HANDLE fresh = CreateFileW(hive->temporary, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    HANDLE target = spp_open(hive->path, GENERIC_READ | GENERIC_WRITE | READ_CONTROL, OPEN_EXISTING);
    BOOL ok = fresh != INVALID_HANDLE_VALUE && target != INVALID_HANDLE_VALUE;
    if (ok && GetFileAttributesW(hive->backup) == INVALID_FILE_ATTRIBUTES) {
        HANDLE backup = spp_open(hive->backup, GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, CREATE_NEW);
        ok = backup != INVALID_HANDLE_VALUE && wintrust_copy(target, backup) &&
             spp_restore_metadata(target, backup) == ERROR_SUCCESS;
        if (backup != INVALID_HANDLE_VALUE)
            CloseHandle(backup);
        if (ok)
            wprintf(L"Previous offline SOFTWARE hive retained at %ls.\n", hive->backup);
        else
            DeleteFileW(hive->backup);
    }
    LARGE_INTEGER size;
    if (ok)
        ok = GetFileSizeEx(fresh, &size) && size.QuadPart > 0 && wintrust_copy(fresh, target);
    if (ok) {
        LARGE_INTEGER end;
        ok = GetFileSizeEx(fresh, &end) && SetFilePointerEx(target, end, NULL, FILE_BEGIN) &&
             SetEndOfFile(target) && FlushFileBuffers(target);
    }
    if (fresh != INVALID_HANDLE_VALUE)
        CloseHandle(fresh);
    if (target != INVALID_HANDLE_VALUE)
        CloseHandle(target);
    DeleteFileW(hive->temporary);
    if (!ok)
        fwprintf(stderr, L"Cannot replace the offline SOFTWARE hive %ls.\n", hive->path);
    return ok;
}

/* offreg only creates one key level at a time, so build the path step by step. */
static DWORD wintrust_hive_path(WintrustHive *hive, const wchar_t *path)
{
    wchar_t partial[512] = {0};
    const wchar_t *cursor = path;
    while (*cursor) {
        const wchar_t *slash = wcschr(cursor, L'\\');
        size_t length = slash ? (size_t)(slash - cursor) : wcslen(cursor);
        if (wcslen(partial) + length + 2 >= ARRAYSIZE(partial))
            return ERROR_INVALID_NAME;
        if (partial[0])
            wcscat(partial, L"\\");
        wcsncat(partial, cursor, length);
        SlKey key = NULL;
        DWORD error = hive->api.CreateKey(hive->hive, partial, NULL, 0, NULL, &key, NULL);
        if (key)
            hive->api.CloseKey(key);
        if (error)
            return error;
        cursor += length;
        if (*cursor == L'\\')
            ++cursor;
    }
    return ERROR_SUCCESS;
}

/* True when the Blob of one store key is a certificate with our subject. */
static BOOL wintrust_offline_matches(WintrustHive *hive, const wchar_t *key, size_t*unused)
{
    (void)unused;
    DWORD type = 0, size = 0;
    if (hive->api.GetValue(hive->hive, key, L"Blob", &type, NULL, &size) || !size || size > 65536)
        return FALSE;
    BYTE *der = malloc(size);
    if (!der)
        return FALSE;
    BOOL ok = !hive->api.GetValue(hive->hive, key, L"Blob", &type, der, &size);
    PCCERT_CONTEXT cert = ok ? CertCreateCertificateContext(X509_ASN_ENCODING, der, size) : NULL;
    if (cert) {
        wchar_t subject[256];
        ok = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, ARRAYSIZE(subject)) > 1 &&
             !wcscmp(subject, WINTRUST_SUBJECT_NAME);
        CertFreeCertificateContext(cert);
    } else {
        ok = FALSE;
    }
    free(der);
    return ok;
}

/* Remove every certificate this package installed from the offline stores. */
static BOOL wintrust_offline_untrust(WintrustHive *hive)
{
    static const wchar_t *const stores[] = {L"Root", L"TrustedPublisher"};
    BOOL ok = TRUE;
    for (unsigned i = 0; ok && i < ARRAYSIZE(stores); ++i) {
        wchar_t path[256];
        if (swprintf(path, ARRAYSIZE(path), L"Microsoft\\SystemCertificates\\%ls\\Certificates", stores[i]) < 0)
            return FALSE;
        SlKey certificates = NULL;
        DWORD error = hive->api.OpenKey(hive->hive, path, &certificates);
        if (error == ERROR_FILE_NOT_FOUND)
            continue;
        if (error) {
            fwprintf(stderr, L"Cannot open the offline %ls store (Win32 %lu).\n", stores[i], error);
            return FALSE;
        }
        for (unsigned index = 0, guard = 0; guard < 4096; ++guard) {
            wchar_t name[256];
            DWORD count = ARRAYSIZE(name);
            error = hive->api.EnumKey(certificates, index, name, &count, NULL, NULL, NULL);
            if (error == ERROR_NO_MORE_ITEMS)
                break;
            if (error) {
                fwprintf(stderr, L"Cannot enumerate the offline %ls store (Win32 %lu).\n", stores[i], error);
                ok = FALSE;
                break;
            }
            wchar_t full[512];
            if (swprintf(full, ARRAYSIZE(full), L"%ls\\%ls", path, name) < 0) {
                ok = FALSE;
                break;
            }
            if (!wintrust_offline_matches(hive, full, NULL)) {
                ++index;
                continue;
            }
            error = hive->api.DeleteKey(certificates, name);
            if (error && error != ERROR_FILE_NOT_FOUND) {
                fwprintf(stderr, L"Cannot remove the local certificate from the offline %ls store (Win32 %lu).\n",
                         stores[i], error);
                ok = FALSE;
                break;
            }
            wprintf(L"Removed the local certificate from the offline %ls store.\n", stores[i]);
        }
        hive->api.CloseKey(certificates);
    }
    return ok;
}

/* Install the local certificate as a trusted root and trusted publisher. */
static BOOL wintrust_offline_trust(const wchar_t *root, const NttpCertificate *certificate, BOOL add)
{
    WintrustHive hive;
    if (!wintrust_hive_load(&hive, root)) {
        fwprintf(stderr, L"Cannot open %ls\\Windows\\System32\\config\\SOFTWARE. The files are signed, but the "
                         L"certificate was not installed; point the mode at the offline Windows root.\n", root);
        return FALSE;
    }
    BOOL ok;
    if (!add) {
        ok = wintrust_offline_untrust(&hive);
    } else {
        wchar_t thumb[41];
        ok = wintrust_thumbprint(certificate, thumb);
        static const wchar_t *const stores[] = {L"Root", L"TrustedPublisher"};
        for (unsigned i = 0; ok && i < ARRAYSIZE(stores); ++i) {
            wchar_t key[256];
            if (swprintf(key, ARRAYSIZE(key), L"Microsoft\\SystemCertificates\\%ls\\Certificates\\%ls",
                         stores[i], thumb) < 0) {
                ok = FALSE;
                break;
            }
            DWORD error = wintrust_hive_path(&hive, key);
            if (!error)
                error = sl_set(&hive.api, hive.hive, key, L"Blob", REG_BINARY,
                               certificate->der, certificate->size);
            if (error) {
                fwprintf(stderr, L"Cannot write the local certificate into the offline %ls store (Win32 %lu).\n",
                         stores[i], error);
                ok = FALSE;
            }
        }
    }
    if (ok)
        ok = wintrust_hive_publish(&hive);
    else
        wintrust_hive_close(&hive);
    return ok;
}

/* ---- offline mode ---- */

typedef struct {
    NttpSigner signer;
    SipApi sip;
    NttpCertificate certificate;
    BOOL signed_something;
} WintrustSigner;

static BOOL wintrust_offline_post(BCRYPT_ALG_HANDLE algorithm, OfflineEdit *edit, void *context)
{
    WintrustSigner *signer = context;
    if (!signer_sign(&signer->signer, &signer->sip, edit->path)) {
        fwprintf(stderr, L"Cannot sign %ls.\n", edit->path);
        return FALSE;
    }
    HANDLE file = spp_open(edit->path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
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
    if (ok) {
        memcpy(edit->after.sha, signed_image.sha, sizeof edit->after.sha);
        edit->after.size = signed_image.size;
    }
    free(signed_image.data);
    if (!ok)
        return FALSE;
    if (!signer_verify(edit->path)) {
        fwprintf(stderr, L"The embedded signature of %ls does not verify.\n", edit->path);
        return FALSE;
    }
    wprintf(L"  signed with the local certificate  SHA-256 %hs\n", edit->after.sha);
    signer->certificate = signer->signer.certificate;
    signer->signed_something = TRUE;
    return TRUE;
}

static BOOL wintrust_live(BCRYPT_ALG_HANDLE algorithm, BOOL restore);

/* A path inside the running Windows installation cannot be rewritten in place;
   the staged live flow does that instead. */
static BOOL wintrust_running(const wchar_t *path)
{
    wchar_t live[PATH_SIZE], live_final[OFFLINE_NT_PATH], candidate[OFFLINE_NT_PATH];
    UINT length = GetSystemWindowsDirectoryW(live, PATH_SIZE);
    DWORD attributes = GetFileAttributesW(path);
    if (!length || length >= PATH_SIZE || attributes == INVALID_FILE_ATTRIBUTES ||
        !offline_directory(live, live_final))
        return FALSE;
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        if (!offline_directory(path, candidate))
            return FALSE;
    } else {
        HANDLE file = CreateFileW(path, FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        if (file == INVALID_HANDLE_VALUE)
            return FALSE;
        BOOL resolved = offline_path_name(file, candidate);
        CloseHandle(file);
        if (!resolved)
            return FALSE;
    }
    /* The live tree itself, a path inside it, or a volume root that contains it
       (an argument such as C:\ points at the parent of C:\Windows). */
    return !_wcsicmp(candidate, live_final) || offline_under(candidate, live_final) ||
           offline_under(live_final, candidate);
}

static BOOL wintrust_offline(BCRYPT_ALG_HANDLE algorithm, const wchar_t *argument, BOOL restore)
{
    wchar_t path[PATH_SIZE], parent[PATH_SIZE], base[PATH_SIZE];
    InputKind input;
    PatchScope scope;
    if (!normalize(path, argument) || !patch_input_kind(path, &input)) {
        fwprintf(stderr, L"Specify the offline Windows root, the extracted folder, or the file.\n");
        return FALSE;
    }
    if (wintrust_running(path)) {
        wprintf(L"%ls is the running Windows installation. Using the staged replacement: the\n"
                L"modules are signed here, the certificate is trusted here, and the files are\n"
                L"replaced at the next start.\n", path);
        return wintrust_live(algorithm, restore);
    }
    base[0] = L'\0';
    if (input == INPUT_FILE) {
        if (!patch_parent_directory(path, parent) || !patch_scope_init(&scope, parent))
            return FALSE;
    } else {
        if (!patch_scope_init(&scope, path))
            return FALSE;
        wcsncpy(base, path, PATH_SIZE - 1);
        base[PATH_SIZE - 1] = L'\0';
    }

    if (restore) {
        RestoreCount count = {0};
        NttpCertificate certificate = {0};
        BOOL have_certificate = FALSE, ok = TRUE;
        if (input == INPUT_FILE) {
            have_certificate = signer_extract(path, WINTRUST_SUBJECT_NAME, &certificate);
            ok = restore_one(algorithm, &scope, path, &count);
        } else {
            BOOL flat = input == INPUT_FLAT;
            for (unsigned i = 0; i < WINTRUST_ENTRIES && ok; ++i) {
                if (flat && i >= 2)
                    break;
                wchar_t candidate[PATH_SIZE];
                const wchar_t *relative = flat ? wintrust_targets[i].leaf : wintrust_targets[i].relative;
                if (!build_path(candidate, base, relative) ||
                    GetFileAttributesW(candidate) == INVALID_FILE_ATTRIBUTES)
                    continue;
                if (!have_certificate)
                    have_certificate = signer_extract(candidate, WINTRUST_SUBJECT_NAME, &certificate);
                ok = restore_one(algorithm, &scope, candidate, &count);
            }
        }
        if (ok && input == INPUT_ROOT)
            ok = wintrust_offline_trust(base, &certificate, FALSE);
        else if (ok && have_certificate)
            wprintf(L"The offline SOFTWARE hive was not touched: restore trust from the "
                    L"offline Windows root, not from a flat folder.\n");
        if (count.restored)
            wprintf(L"%u certificate module(s) restored in %ls.\n", count.restored,
                    input == INPUT_FILE ? patch_leaf(path) : base);
        else
            wprintf(L"No retained original was found for these modules.\n");
        return ok && count.failed == 0;
    }

    PatchSpec specs[WINTRUST_ENTRIES];
    unsigned char states[WINTRUST_ENTRIES] = {0};
    unsigned count = 0;
    if (input == INPUT_FILE) {
        specs[count++] = (PatchSpec){.relative = path, .name = patch_leaf(path), .required = TRUE,
                                     .skip_unsupported = FALSE, .plan = plan_cert_any,
                                     .build = wintrust_build, .recognized = wintrust_recognized};
    } else {
        BOOL flat = input == INPUT_FLAT;
        for (unsigned i = 0; i < WINTRUST_ENTRIES; ++i) {
            if (flat && i >= 2)
                break;
            specs[count++] = (PatchSpec){
                .relative = flat ? wintrust_targets[i].leaf : wintrust_targets[i].relative,
                .name = wintrust_targets[i].name,
                .required = wintrust_targets[i].kind == 0 && !flat,
                .skip_unsupported = FALSE,
                .plan = wintrust_plan(wintrust_targets[i].kind),
                .build = wintrust_build,
                .recognized = wintrust_recognized
            };
        }
    }

    WintrustSigner signer = {0};
    if (!signer_open(&signer.signer, WINTRUST_SUBJECT))
        return FALSE;
    BOOL ok = patch_specs(algorithm, &scope, input == INPUT_FILE ? NULL : base, specs, count, states,
                          wintrust_offline_post, &signer);
    if (ok && !signer.signed_something) {
        /* Nothing was written: an earlier run already signed these files. */
        for (unsigned i = 0; i < count && !signer.signed_something; ++i) {
            wchar_t candidate[PATH_SIZE];
            if (!build_path(candidate, base, specs[i].relative))
                continue;
            if (signer_extract(candidate, WINTRUST_SUBJECT_NAME, &signer.certificate))
                signer.signed_something = TRUE;
        }
        if (!signer.signed_something && input == INPUT_FILE &&
            signer_extract(path, WINTRUST_SUBJECT_NAME, &signer.certificate))
            signer.signed_something = TRUE;
    }
    BOOL trusted = FALSE;
    if (ok && input == INPUT_ROOT && signer.signed_something) {
        ok = wintrust_offline_trust(base, &signer.certificate, TRUE);
        trusted = ok;
    } else if (ok && signer.signed_something) {
        wprintf(L"Signed, but the offline SOFTWARE hive was not updated: run this mode on the offline\n"
                L"Windows root so the certificate can be installed as a trusted root and publisher.\n");
    }
    unsigned changed_count = 0, already_count = 0;
    for (unsigned i = 0; i < count; ++i) {
        changed_count += states[i] == SPEC_CHANGED;
        already_count += states[i] == SPEC_ALREADY;
    }
    if (ok && !changed_count && !already_count) {
        fwprintf(stderr, L"No wintrust.dll or crypt32.dll was found for this mode. No files changed.\n");
        ok = FALSE;
    }
    patch_report(input == INPUT_FILE ? NULL : base, states, count);
    signer_close(&signer.signer);
    if (!ok)
        return FALSE;
    if (trusted)
        wprintf(L"The modules carry a local signature, trusted by this image's Root and\n"
                L"TrustedPublisher stores. Undo with /wintrust-approval-restore.\n");
    return TRUE;
}


/* ---- live mode: stage, trust, replace at the next start ---- */

enum { WINTRUST_RECEIPT_VERSION = 1 };

typedef struct {
    wchar_t relative[24];   /* System32\\wintrust.dll */
    wchar_t staged[24];     /* s0-wintrust.dll */
    char original[65];      /* hex SHA-256 of the file before the change */
    char signed_hash[65];   /* hex SHA-256 of the staged file */
} WintrustEntry;

typedef struct {
    DWORD version;
    wchar_t id[33];
    NttpCertificate certificate;
    DWORD count;
    WintrustEntry entries[WINTRUST_ENTRIES];
} WintrustReceipt;

static BOOL wintrust_live_dir(const wchar_t *id, wchar_t dir[MAX_PATH])
{
    wchar_t windows[MAX_PATH];
    UINT length = GetWindowsDirectoryW(windows, ARRAYSIZE(windows));
    return length && length < ARRAYSIZE(windows) &&
           swprintf(dir, MAX_PATH, L"%ls\\" WINTRUST_STAGE_PREFIX L"%ls", windows, id) > 0;
}

static BOOL wintrust_live_target(const wchar_t *relative, wchar_t target[MAX_PATH])
{
    wchar_t windows[MAX_PATH];
    UINT length = GetWindowsDirectoryW(windows, ARRAYSIZE(windows));
    return length && length < ARRAYSIZE(windows) &&
           swprintf(target, MAX_PATH, L"%ls\\%ls", windows, relative) > 0;
}

static BOOL wintrust_trust_check(SipApi *sip, const wchar_t *path)
{
    typedef LONG (WINAPI *TrustFn)(HWND, GUID *, void *);
    FARPROC address = sip->wintrust ? GetProcAddress(sip->wintrust, "WinVerifyTrust") : NULL;
    TrustFn verify = NULL;
    if (address)
        memcpy(&verify, &address, sizeof verify);
    if (!verify)
        return FALSE;
    WINTRUST_FILE_INFO file = {.cbStruct = sizeof file, .pcwszFilePath = path};
    WINTRUST_DATA trust = {.cbStruct = sizeof trust, .dwUIChoice = WTD_UI_NONE,
        .dwStateAction = WTD_STATEACTION_VERIFY, .dwUnionChoice = WTD_CHOICE_FILE, .pFile = &file};
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = verify(INVALID_HANDLE_VALUE, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    verify(INVALID_HANDLE_VALUE, &action, &trust);
    if (status)
        fwprintf(stderr, L"The local signature of %ls does not verify (0x%08lx).\n", path, (unsigned long)status);
    return status == 0;
}

/* Patch, strip and sign one running-system module into the staging folder. */
static BOOL wintrust_live_stage(BCRYPT_ALG_HANDLE algorithm, WintrustSigner *signer, const wchar_t *target,
                                const wchar_t *staged, const wchar_t *original, WintrustReceipt *receipt)
{
    if (wintrust_recognized(target, NULL)) {
        wprintf(L"%ls\n  already carries this package's local signature. Skipped.\n", target);
        return TRUE;
    }
    HANDLE source = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (source == INVALID_HANDLE_VALUE) {
        ci_io_error(L"read", target, GetLastError());
        return FALSE;
    }
    Output current = {0};
    BOOL ok = offline_read(source, &current, algorithm);
    CloseHandle(source);
    if (!ok) {
        free(current.data);
        return FALSE;
    }
    Image image;
    Plan edits = {0};
    PatchPlan plan = !_wcsicmp(patch_leaf(target), L"wintrust.dll") ? plan_wintrust : plan_crypt32;
    if (!image_open_arch(&image, current.data, current.size, TRUE) || !plan(&image, &edits) ||
        !(edits.count || edits.existing)) {
        fwprintf(stderr, L"Unsupported or ambiguous structure in %ls. No files changed.\n", target);
        free(current.data);
        return FALSE;
    }
    Output after = {0};
    after.size = current.size;
    after.data = malloc(after.size);
    ok = after.data != NULL;
    if (ok) {
        memcpy(after.data, current.data, after.size);
        for (unsigned i = 0; i < edits.count; ++i)
            memcpy(after.data + edits.edits[i].at, edits.edits[i].bytes, edits.edits[i].length);
        ok = signer_strip_signature(after.data, &after.size) && fix_checksum(after.data, after.size);
    }
    free(current.data);
    if (!ok) {
        free(after.data);
        return FALSE;
    }
    HANDLE file = CreateFileW(staged, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    ok = file != INVALID_HANDLE_VALUE && WriteFile(file, after.data, after.size, &written, NULL) &&
         written == after.size && FlushFileBuffers(file);
    free(after.data);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok || !signer_sign(&signer->signer, &signer->sip, staged) || !signer_verify(staged)) {
        fwprintf(stderr, L"Cannot sign %ls.\n", staged);
        return FALSE;
    }
    signer->certificate = signer->signer.certificate;
    signer->signed_something = TRUE;
    /* The replacement keeps the timestamps of the file it replaces. */
    FILETIME created_time = {0}, accessed_time = {0}, written_time = {0};
    HANDLE attributes = CreateFileW(target, FILE_READ_ATTRIBUTES | FILE_READ_DATA,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    BOOL have_times = attributes != INVALID_HANDLE_VALUE &&
                      GetFileTime(attributes, &created_time, &accessed_time, &written_time);
    if (attributes != INVALID_HANDLE_VALUE)
        CloseHandle(attributes);
    if (have_times)
        patch_keep_times(staged, &created_time, &accessed_time, &written_time);

    HANDLE read_source = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                     NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    DWORD error = read_source == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    /* The verified copy reads the destination back, so it needs read access too. */
    /* The copy is swapped back on restore, so it keeps the owner, DACL and time. */
    HANDLE copy = CreateFileW(original, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!error && copy == INVALID_HANDLE_VALUE)
        error = GetLastError();
    ok = read_source != INVALID_HANDLE_VALUE && copy != INVALID_HANDLE_VALUE &&
         spp_copy_verified(read_source, copy) && FlushFileBuffers(copy) &&
         spp_restore_metadata(read_source, copy) == ERROR_SUCCESS &&
         (!have_times || patch_keep_times(original, &created_time, &accessed_time, &written_time));
    if (!error && !ok)
        error = GetLastError();
    if (read_source != INVALID_HANDLE_VALUE)
        CloseHandle(read_source);
    if (copy != INVALID_HANDLE_VALUE)
        CloseHandle(copy);
    if (!ok) {
        fwprintf(stderr, L"Cannot retain the current %ls (Win32 %lu). The target was not changed.\n",
                 target, error);
        return FALSE;
    }

    if (receipt->count < WINTRUST_ENTRIES) {
        WintrustEntry *entry = &receipt->entries[receipt->count++];
        const wchar_t *leaf = patch_leaf(target);
        const wchar_t *folder = wcsstr(target, L"\\SysWOW64\\") ? L"SysWOW64" : L"System32";
        swprintf(entry->relative, ARRAYSIZE(entry->relative), L"%ls\\%ls", folder, leaf);
        swprintf(entry->staged, ARRAYSIZE(entry->staged), L"%ls", patch_leaf(staged));
        HANDLE handle = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        Output hash = {0};
        ok = handle != INVALID_HANDLE_VALUE && offline_read(handle, &hash, algorithm);
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
        if (ok) memcpy(entry->original, hash.sha, sizeof entry->original);
        free(hash.data);
        handle = CreateFileW(staged, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                             FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        Output signed_hash = {0};
        ok = ok && handle != INVALID_HANDLE_VALUE && offline_read(handle, &signed_hash, algorithm);
        if (handle != INVALID_HANDLE_VALUE)
            CloseHandle(handle);
        if (ok) memcpy(entry->signed_hash, signed_hash.sha, sizeof entry->signed_hash);
        free(signed_hash.data);
    }
    wprintf(L"%ls\n  staged at %ls and signed with the local certificate.\n", target, staged);
    return ok;
}

static BOOL wintrust_live(BCRYPT_ALG_HANDLE algorithm, BOOL restore)
{
    WintrustReceipt receipt = {0};
    DWORD size = sizeof receipt;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, WINTRUST_RECEIPT, L"Receipt", RRF_RT_REG_BINARY,
                                  NULL, &receipt, &size);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        return FALSE;

    if (restore) {
        if (status == ERROR_FILE_NOT_FOUND) {
            fwprintf(stderr, L"No /wintrust operation is recorded.\n");
            return FALSE;
        }
        if (size != sizeof receipt || receipt.version != WINTRUST_RECEIPT_VERSION || receipt.id[32] ||
            !receipt.count || receipt.count > WINTRUST_ENTRIES)
            return FALSE;
        wchar_t dir[MAX_PATH];
        if (!wintrust_live_dir(receipt.id, dir))
            return FALSE;
        BOOL ok = TRUE;
        for (unsigned i = 0; i < receipt.count; ++i) {
            wchar_t target[MAX_PATH], original[MAX_PATH];
            if (!wintrust_live_target(receipt.entries[i].relative, target) ||
                swprintf(original, MAX_PATH, L"%ls\\%ls.original", dir, receipt.entries[i].staged) < 0) {
                ok = FALSE;
                continue;
            }
            if (!patch_schedule_replace(original, target)) {
                ok = FALSE;
            } else {
                wprintf(L"Restore of %ls scheduled for the next start.\n", target);
            }
        }
        if (ok)
            ok = signer_live_trust(&receipt.certificate, FALSE);
        if (ok) {
            RegDeleteKeyW(HKEY_LOCAL_MACHINE, WINTRUST_RECEIPT);
            wprintf(L"The certificate was removed. Restart to finish the restore.\n");
        }
        return ok;
    }

    if (status == ERROR_SUCCESS) {
        fwprintf(stderr, L"A /wintrust operation is already recorded. Run /wintrust-restore and restart first.\n");
        return FALSE;
    if (!restore && !patch_live_guard(L"/wintrust"))
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
    if (!enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return FALSE;
    }

    WintrustSigner signer = {0};
    if (!signer_open(&signer.signer, WINTRUST_SUBJECT) || !signer_sip(&signer.sip)) {
        fwprintf(stderr, L"Cannot prepare the local signing certificate.\n");
        return FALSE;
    }
    BYTE random[16];
    receipt.version = WINTRUST_RECEIPT_VERSION;
    if (BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        signer_close(&signer.signer);
        return FALSE;
    }
    for (unsigned i = 0; i < sizeof random; ++i)
        swprintf(receipt.id + i * 2, 3, L"%02x", random[i]);
    wchar_t dir[MAX_PATH];
    if (!wintrust_live_dir(receipt.id, dir)) {
        signer_close(&signer.signer);
        return FALSE;
    }
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
                                                              SDDL_REVISION_1, &descriptor, NULL)) {
        signer_close(&signer.signer);
        return FALSE;
    }
    SECURITY_ATTRIBUTES attributes = {sizeof attributes, descriptor, FALSE};
    BOOL ok = CreateDirectoryW(dir, &attributes);
    LocalFree(descriptor);
    if (!ok) {
        wprintf(L"Cannot create %ls (Win32 %lu).\n", dir, GetLastError());
        signer_close(&signer.signer);
        return FALSE;
    }

    static const wchar_t *const relatives[WINTRUST_ENTRIES] = {
        L"System32\\wintrust.dll", L"System32\\crypt32.dll",
        L"SysWOW64\\wintrust.dll", L"SysWOW64\\crypt32.dll"
    };
    static const wchar_t *const staged_names[WINTRUST_ENTRIES] = {
        L"s0-wintrust.dll", L"s1-crypt32.dll", L"s2-wintrust.dll", L"s3-crypt32.dll"
    };
    for (unsigned i = 0; ok && i < WINTRUST_ENTRIES; ++i) {
        wchar_t target[MAX_PATH], staged[MAX_PATH], original[MAX_PATH];
        if (!wintrust_live_target(relatives[i], target) ||
            GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES)
            continue;
        if (swprintf(staged, MAX_PATH, L"%ls\\%ls", dir, staged_names[i]) < 0 ||
            swprintf(original, MAX_PATH, L"%ls\\%ls.original", dir, staged_names[i]) < 0) {
            ok = FALSE;
            break;
        }
        ok = wintrust_live_stage(algorithm, &signer, target, staged, original, &receipt);
    }
    if (ok && !receipt.count) {
        fwprintf(stderr, L"No module needed the local signature. Nothing staged.\n");
        ok = FALSE;
    }
    if (ok)
        ok = signer_live_trust(&signer.certificate, TRUE);
    for (unsigned i = 0; ok && i < receipt.count; ++i) {
        wchar_t dir_path[MAX_PATH], staged[MAX_PATH];
        if (!wintrust_live_dir(receipt.id, dir_path) ||
            swprintf(staged, MAX_PATH, L"%ls\\%ls", dir_path, receipt.entries[i].staged) < 0)
            ok = FALSE;
        else
            ok = wintrust_trust_check(&signer.sip, staged);
    }
    if (ok) {
        /* Journal first: a restore after this point can always find the copies. */
        HKEY key = NULL;
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, WINTRUST_RECEIPT, 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL) ||
            RegSetValueExW(key, L"Receipt", 0, REG_BINARY, (const BYTE *)&receipt, sizeof receipt) ||
            RegFlushKey(key)) {
            fwprintf(stderr, L"Cannot store the /wintrust journal (Win32 %lu).\n", GetLastError());
            ok = FALSE;
        }
        if (key)
            RegCloseKey(key);
    }
    BOOL queued = ok;
    for (unsigned i = 0; ok && i < receipt.count; ++i) {
        wchar_t dir_path[MAX_PATH], staged[MAX_PATH], target[MAX_PATH];
        if (!wintrust_live_dir(receipt.id, dir_path) ||
            swprintf(staged, MAX_PATH, L"%ls\\%ls", dir_path, receipt.entries[i].staged) < 0 ||
            !wintrust_live_target(receipt.entries[i].relative, target)) {
            ok = FALSE;
            break;
        }
        if (!patch_schedule_replace(staged, target)) {
            ok = FALSE;
            break;
        }
    }
    if (ok) {
        wchar_t dir_path[MAX_PATH];
        unsigned expected = receipt.count;
        if (wintrust_live_dir(receipt.id, dir_path)) {
            unsigned found = patch_pending_count(dir_path);
            wprintf(L"Queued %u of %u replacement(s) in PendingFileRenameOperations.\n", found, expected);
            if (found < expected) {
                fwprintf(stderr, L"The pending-rename list does not hold every replacement, so a restart\n"
                                 L"would apply only part of the patch. Nothing else was changed; run\n"
                                 L"/wintrust-restore and reboot, then retry.\n");
                ok = FALSE;
                queued = FALSE;
            }
        }
    }
    if (!ok && queued)
        fwprintf(stderr, L"Scheduling failed before the certificate was installed. Nothing was queued.\n");
    signer_close(&signer.signer);
    if (!ok) {
        if (receipt.count)
            wprintf(L"The operation did not complete. Run /wintrust-restore and restart to be safe.\n");
        return FALSE;
    }
    wprintf(L"%lu signed module(s) are staged and the certificate is trusted.\n"
            L"Restart now: the replacement is applied before the drivers load.\n"
            L"If the next start fails, run /wintrust-restore from here, or /wintrust-approval-restore\n"
            L"from WinPE on the offline image, and restart again.\n", (unsigned long)receipt.count);
    return TRUE;
}


