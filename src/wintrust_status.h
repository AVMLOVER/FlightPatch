/* /wintrust-status - read-only report of what the signature layer sees now.

   It answers the question that decides the next step: does the patched trust
   path accept the module and the application that will not start, and is the
   local certificate trusted? Nothing is written. */

typedef struct {
    HMODULE module;
    LONG (WINAPI *verify)(HWND, GUID *, void *);
    HRESULT (WINAPI *signature_info)(LPCWSTR, HANDLE, DWORD, void *, PCCERT_CONTEXT *, HANDLE *);
} StatusApi;

static BOOL status_api(StatusApi *api)
{
    if (api->module)
        return TRUE;
    api->module = LoadLibraryW(L"wintrust.dll");
    if (!api->module)
        return FALSE;
    FARPROC address = GetProcAddress(api->module, "WinVerifyTrust");
    memcpy(&api->verify, &address, sizeof address);
    address = GetProcAddress(api->module, "WTGetSignatureInfo");
    memcpy(&api->signature_info, &address, sizeof address);
    return api->verify != NULL;
}

static LONG status_verify(StatusApi *api, const wchar_t *path)
{
    WINTRUST_FILE_INFO file = {.cbStruct = sizeof file, .pcwszFilePath = path};
    WINTRUST_DATA trust = {.cbStruct = sizeof trust, .dwUIChoice = WTD_UI_NONE,
        .dwStateAction = WTD_STATEACTION_VERIFY, .dwUnionChoice = WTD_CHOICE_FILE, .pFile = &file};
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = api->verify(INVALID_HANDLE_VALUE, &action, &trust);
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    api->verify(INVALID_HANDLE_VALUE, &action, &trust);
    return status;
}

/* The same query the elevation and package paths use, including catalogs. */
static BOOL status_selected(StatusApi *api, const wchar_t *path, HRESULT *result, DWORD *state,
                            wchar_t subject[256])
{
    if (!api->signature_info)
        return FALSE;
    struct {
        DWORD size, state, type, signature_flags, info_flags;
        wchar_t *display_name;
        DWORD display_length;
        wchar_t *publisher;
        DWORD publisher_length;
        wchar_t *url;
        DWORD url_length;
        BYTE *hash;
        DWORD hash_size;
        BOOL os_binary;
    } info = {.size = sizeof info};
    /* The query resolves catalogs only with some flag combinations, so try the
       same sets the MMC helper uses and keep the best answer. */
    static const DWORD flags[] = {0x0807, 0x1807, 0x2807, 0x3807};
    *result = 1;
    *state = 0;
    subject[0] = L'\0';
    DWORD best = 0;
    for (unsigned i = 0; i < ARRAYSIZE(flags); ++i) {
        HANDLE handle = NULL;
        PCCERT_CONTEXT cert = NULL;
        memset(&info, 0, sizeof info);
        info.size = sizeof info;
        HRESULT current = api->signature_info(path, NULL, flags[i], &info, &cert, &handle);
        if (info.state > best || i == 0) {
            best = info.state;
            *result = current;
            *state = info.state;
            subject[0] = L'\0';
            if (cert)
                CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, 256);
        }
        if (cert)
            CertFreeCertificateContext(cert);
        if (handle) {
            WINTRUST_DATA close = {.cbStruct = sizeof close, .dwStateAction = WTD_STATEACTION_CLOSE,
                                   .hWVTStateData = handle};
            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            api->verify(INVALID_HANDLE_VALUE, &action, &close);
        }
        if (info.state >= 6)
            break;
    }
    return TRUE;
}

static BOOL status_certificate_trusted(const NttpCertificate *certificate, BOOL *root, BOOL *publisher)
{
    *root = FALSE;
    *publisher = FALSE;
    static const wchar_t *const stores[2] = {L"ROOT", L"TrustedPublisher"};
    BOOL *const results[2] = {root, publisher};
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, stores[0]);
    HCERTSTORE publisher_store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0,
                                               CERT_SYSTEM_STORE_LOCAL_MACHINE, stores[1]);
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, certificate->der, certificate->size);
    if (roots && cert)
        *root = CertFindCertificateInStore(roots, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, cert, NULL) != NULL;
    if (publisher_store && cert)
        *publisher = CertFindCertificateInStore(publisher_store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING,
                                                cert, NULL) != NULL;
    if (cert)
        CertFreeCertificateContext(cert);
    if (roots)
        CertCloseStore(roots, 0);
    if (publisher_store)
        CertCloseStore(publisher_store, 0);
    return TRUE;
}

static void status_report(StatusApi *api, const wchar_t *path, BOOL local_signed,
                          const NttpCertificate *certificate, BOOL have_certificate)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"%ls: absent\n", path);
        return;
    }
    wprintf(L"%ls\n", path);
    if (local_signed) {
        wprintf(L"  signed here      : yes (NT Timebomb Patch local certificate)\n");
        wprintf(L"  signature intact : %ls\n", signer_verify(path) ? L"yes" : L"no");
    } else {
        wprintf(L"  signed here      : no\n");
    }
    if (have_certificate) {
        BOOL root = FALSE, publisher = FALSE;
        status_certificate_trusted(certificate, &root, &publisher);
        wprintf(L"  certificate      : Root %ls, TrustedPublisher %ls\n",
                root ? L"trusted" : L"missing", publisher ? L"trusted" : L"missing");
    }
    wprintf(L"  WinVerifyTrust   : 0x%08lX%ls\n", (unsigned long)status_verify(api, path),
            status_verify(api, path) == 0 ? L" (trusted)" : L"");
    HRESULT result = 0;
    DWORD state = 0;
    wchar_t subject[256];
    if (status_selected(api, path, &result, &state, subject))
        wprintf(L"  signature query  : 0x%08lX state %lu%ls%ls\n", (unsigned long)result, state,
                subject[0] ? L" signer " : L"", subject);
}

static BOOL patch_wintrust_status(BCRYPT_ALG_HANDLE algorithm, const wchar_t *extra)
{
    (void)algorithm;
    StatusApi api = {0};
    if (!status_api(&api)) {
        fwprintf(stderr, L"Cannot load wintrust.dll in this environment.\n");
        return FALSE;
    }
    wchar_t windows[PATH_SIZE];
    UINT length = GetSystemWindowsDirectoryW(windows, PATH_SIZE);
    if (!length || length >= PATH_SIZE) {
        fwprintf(stderr, L"Cannot resolve the running Windows directory.\n");
        return FALSE;
    }
    wprintf(L"Signature state of the patched modules and the components that fail to start.\n");
    static const wchar_t *const relatives[] = {
        L"System32\\wintrust.dll", L"System32\\crypt32.dll",
        L"SysWOW64\\wintrust.dll", L"SysWOW64\\crypt32.dll",
        L"System32\\osk.exe", L"System32\\Narrator.exe", L"System32\\Magnify.exe",
        L"System32\\mmc.exe", L"System32\\LicensingUI.exe"
    };
    for (unsigned i = 0; i < ARRAYSIZE(relatives); ++i) {
        wchar_t path[PATH_SIZE];
        if (!build_path(path, windows, relatives[i]))
            continue;
        NttpCertificate certificate = {0};
        BOOL local_signed = signer_extract(path, WINTRUST_SUBJECT_NAME, &certificate);
        status_report(&api, path, local_signed, &certificate, local_signed);
    }
    /* AppInfo carries the UIAccess and elevation decisions; report whether this
       package rewrote it and whether the service is running. */
    {
        wchar_t appinfo[PATH_SIZE], backup[PATH_SIZE];
        if (build_path(appinfo, windows, L"System32\\appinfo.dll") &&
            swprintf(backup, PATH_SIZE, L"%ls.nttp-mmc-original", appinfo) > 0) {
            wprintf(L"%ls\n", appinfo);
            wprintf(L"  mmc-approval     : %ls\n",
                    GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES ?
                    L"rewritten by this package (backup present)" : L"original or not touched");
            SC_HANDLE manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
            SC_HANDLE service = manager ? OpenServiceW(manager, L"AppInfo", SERVICE_QUERY_STATUS) : NULL;
            SERVICE_STATUS status = {0};
            if (service && QueryServiceStatus(service, &status))
                wprintf(L"  AppInfo service  : %s\n",
                        status.dwCurrentState == SERVICE_RUNNING ? "running" :
                        status.dwCurrentState == SERVICE_STOPPED ? "stopped" : "in transition");
            else
                wprintf(L"  AppInfo service  : cannot query (Win32 %lu)\n", GetLastError());
            if (service)
                CloseServiceHandle(service);
            if (manager)
                CloseServiceHandle(manager);
        }
    }
    if (extra) {
        wchar_t path[PATH_SIZE];
        if (normalize(path, extra)) {
            NttpCertificate certificate = {0};
            BOOL local_signed = signer_extract(path, WINTRUST_SUBJECT_NAME, &certificate);
            status_report(&api, path, local_signed, &certificate, local_signed);
        }
    }
    wprintf(L"Read-only report. A component that still fails with every check above at 0 is blocked by\n"
            L"something other than certificate validation: capture its own error code and the\n"
            L"Application-Experience, AppModel-Runtime and CodeIntegrity event logs.\n");
    return TRUE;
}

static int run_wintrust_status(BCRYPT_ALG_HANDLE algorithm, int argc, wchar_t **argv)
{
    const wchar_t *extra = argc == 3 ? argv[2] : NULL;
    if (argc != 2 && argc != 3) {
        fwprintf(stderr, L"Usage: nttimebomb /wintrust-status [FILE]\n");
        return 2;
    }
    BOOL ok = patch_wintrust_status(algorithm, extra);
    return ok ? 0 : 1;
}
