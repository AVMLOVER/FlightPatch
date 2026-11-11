/* Local Authenticode signing for the files this package rewrites.

   A modified Microsoft binary loses its signature, and the tested preview builds
   reject such an image at load (0xc000021a with 0xc0000428). This module replaces
   the invalid signature with a local one: an ephemeral RSA key in the Microsoft
   software key store, a self-signed code-signing certificate, and the matching
   PKCS#7 blob embedded through the SIP APIs. The certificate is what the caller
   installs into the target's Root and TrustedPublisher stores, exactly like the
   MMC exception that the package already uses.

   Shared by mmc.c and the /wintrust modes. */

typedef struct {
    DWORD size;
    BYTE der[2048];
} NttpCertificate;

typedef struct {
    NttpCertificate certificate;
    BOOL ncrypt;                 /* key store provider, when available */
    NCRYPT_PROV_HANDLE provider;
    NCRYPT_KEY_HANDLE key;
    HCRYPTPROV capi;             /* CryptoAPI fallback, used in WinPE */
    HCRYPTKEY capi_key;
    wchar_t container[64];
    wchar_t provider_name[64];
    DWORD provider_type;
    const char *hash_oid;        /* digest used by SIP and by the CMS signer */
    const char *signature_oid;   /* signature algorithm of the certificate */
    PCCERT_CONTEXT cert;
} NttpSigner;

/* SIP entry points live in wintrust.dll; resolve them at run time so a broken
   or replaced wintrust.dll cannot stop the tool from starting. */
typedef BOOL (WINAPI *SipRetrieveSubjectGuidFn)(LPCWSTR, HANDLE, GUID *);
typedef BOOL (WINAPI *SipCreateIndirectDataFn)(SIP_SUBJECTINFO *, DWORD *, SIP_INDIRECT_DATA *);
typedef BOOL (WINAPI *SipPutSignedDataMsgFn)(SIP_SUBJECTINFO *, DWORD, DWORD *, DWORD, BYTE *);

typedef struct {
    HMODULE module;      /* crypt32.dll, which carries the SIP helpers */
    HMODULE wintrust;    /* wintrust.dll, which carries WinVerifyTrust */
    SipRetrieveSubjectGuidFn subject_guid;
    SipCreateIndirectDataFn create;
    SipPutSignedDataMsgFn put;
} SipApi;

static BOOL signer_sip(SipApi *api)
{
    if (api->module)
        return TRUE;
    /* CryptSIPRetrieveSubjectGuid is only exported by crypt32.dll; both modules
       export the other two, so either one can satisfy them. */
    api->module = LoadLibraryW(L"crypt32.dll");
    if (!api->module)
        return FALSE;
    api->wintrust = LoadLibraryW(L"wintrust.dll");
#define SIGNER_IMPORT(field, name) do { \
        FARPROC address = GetProcAddress(api->module, name); \
        if (!address && api->wintrust) address = GetProcAddress(api->wintrust, name); \
        memcpy(&api->field, &address, sizeof address); \
        if (!address) return FALSE; \
    } while (0)
    SIGNER_IMPORT(subject_guid, "CryptSIPRetrieveSubjectGuid");
    SIGNER_IMPORT(create, "CryptSIPCreateIndirectData");
    SIGNER_IMPORT(put, "CryptSIPPutSignedDataMsg");
#undef SIGNER_IMPORT
    return TRUE;
}

/* WinPE has no software key store provider, so the signer can create the key
   through CryptoAPI instead. Both paths end in the same self-signed certificate. */
static void signer_close(NttpSigner *signer);

static BOOL signer_open_ncrypt(NttpSigner *signer)
{
    DWORD bits = 2048;
    SECURITY_STATUS status = NCryptOpenStorageProvider(&signer->provider, MS_KEY_STORAGE_PROVIDER, 0);
    const wchar_t *step = L"NCryptOpenStorageProvider";
    if (!status) {
        step = L"NCryptCreatePersistedKey";
        status = NCryptCreatePersistedKey(signer->provider, &signer->key, NCRYPT_RSA_ALGORITHM, NULL, 0, 0);
    }
    if (!status) {
        step = L"NCryptSetProperty";
        status = NCryptSetProperty(signer->key, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bits, sizeof bits, 0);
    }
    if (!status) {
        step = L"NCryptFinalizeKey";
        status = NCryptFinalizeKey(signer->key, 0);
    }
    if (status) {
        const wchar_t *hint = (unsigned long)status == 0x800706D9UL ?
            L" (CNG Key Isolation service unavailable)" :
            (unsigned long)status == 0x80090029UL ? L" (provider not supported)" : L"";
        wprintf(L"Key store provider: %ls failed with 0x%08lX%ls; trying CryptoAPI.\n",
                step, (unsigned long)status, hint);
        if (signer->key) {
            NCryptFreeObject(signer->key);
            signer->key = 0;
        }
        if (signer->provider) {
            NCryptFreeObject(signer->provider);
            signer->provider = 0;
        }
        return FALSE;
    }
    signer->ncrypt = TRUE;
    return TRUE;
}

static const wchar_t *signer_error_hint(DWORD error)
{
    switch (error) {
    case 0x8009001E: return L" (provider DLL not found)";
    case 0x8009001D: return L" (provider DLL not found)";
    case 0x80090016: return L" (key set not found)";
    case 0x8009000D: return L" (no key)";
    case 0x80090010: return L" (permission denied)";
    case 0x80090029: return L" (not supported)";
    case 18: return L" (no more files)";
    default: return L"";
    }
}

/* CryptoAPI providers are the only signing path in environments without the
   software key store. WinPE ships neither, which the caller reports. */
static BOOL signer_open_capi(NttpSigner *signer, const wchar_t *provider, DWORD type)
{
    const wchar_t *label = provider ? provider : L"the default provider";
    wchar_t container[80];
    swprintf(container, ARRAYSIZE(container), L"NTTimebomb-%lu-%lu",
             (unsigned long)GetCurrentProcessId(), (unsigned long)GetTickCount());
    HCRYPTPROV context = 0;
    if (!CryptAcquireContextW(&context, container, provider, type, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
        DWORD error = GetLastError();
        wprintf(L"Cannot create a key container with %ls (0x%08lX %ls); trying its default container.\n",
                label, error, signer_error_hint(error));
        container[0] = L'\0';
        if (!CryptAcquireContextW(&context, NULL, provider, type, CRYPT_SILENT)) {
            error = GetLastError();
            wprintf(L"Cannot open %ls (0x%08lX %ls).\n", label, error, signer_error_hint(error));
            return FALSE;
        }
    }
    HCRYPTKEY key = 0;
    BOOL ok = CryptGenKey(context, AT_SIGNATURE, 2048u << 16, &key);
    if (!ok) {
        DWORD error = GetLastError();
        wprintf(L"Cannot create an RSA signature key with %ls (0x%08lX %ls).\n",
                label, error, signer_error_hint(error));
        CryptReleaseContext(context, 0);
        return FALSE;
    }
    signer->capi = context;
    signer->capi_key = key;
    signer->provider_type = type;
    wcsncpy(signer->provider_name, provider ? provider : L"", ARRAYSIZE(signer->provider_name) - 1);
    /* The certificate needs the container that now holds the key. */
    DWORD size = (DWORD)sizeof signer->container;
    if (!CryptGetProvParam(context, PP_CONTAINER, (BYTE *)signer->container, &size, 0))
        signer->container[0] = L'\0';
    else
        signer->container[ARRAYSIZE(signer->container) - 1] = L'\0';
    return TRUE;
}

static BOOL signer_open(NttpSigner *signer, const wchar_t *subject_name)
{
    memset(signer, 0, sizeof *signer);
    BYTE name[256], usage[64];
    DWORD name_size = sizeof name, usage_size = sizeof usage;
    LPSTR oid = szOID_PKIX_KP_CODE_SIGNING;
    CERT_ENHKEY_USAGE eku = {1, &oid};
    if (!CertStrToNameW(X509_ASN_ENCODING, subject_name, CERT_X500_NAME_STR, NULL, name, &name_size, NULL) ||
        !CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, 0, NULL, usage, &usage_size)) {
        fwprintf(stderr, L"Cannot encode the certificate name (Win32 %lu).\n", GetLastError());
        return FALSE;
    }

    signer->hash_oid = szOID_NIST_sha256;
    signer->signature_oid = szOID_RSA_SHA256RSA;
    if (!signer_open_ncrypt(signer)) {
        if (!signer_open_capi(signer, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES)) {
            if (!signer_open_capi(signer, MS_ENHANCED_PROV_W, PROV_RSA_FULL)) {
                /* The classic provider may only sign with SHA-1. */
                signer->hash_oid = szOID_OIWSEC_sha1;
                signer->signature_oid = szOID_RSA_SHA1RSA;
                if (!signer_open_capi(signer, MS_STRONG_PROV_W, PROV_RSA_FULL) &&
                    !signer_open_capi(signer, MS_ENHANCED_PROV_W, PROV_RSA_SIG) &&
                    !signer_open_capi(signer, NULL, PROV_RSA_FULL)) {
                    fwprintf(stderr,
                             L"No signing provider is available in this environment. WinPE and WinRE do not\n"
                             L"ship the software key store or an RSA cryptographic provider, so a local\n"
                             L"certificate cannot be created here. No target file was changed.\n"
                             L"Run this mode from a full Windows installation with the offline volume\n"
                             L"attached; any architecture build of this tool can service the image.\n");
                    return FALSE;
                }
            }
        }
    }

    CERT_NAME_BLOB subject = {name_size, name};
    CERT_EXTENSION extension = {.pszObjId = szOID_ENHANCED_KEY_USAGE, .Value = {usage_size, usage}};
    CERT_EXTENSIONS extensions = {1, &extension};
    CRYPT_ALGORITHM_IDENTIFIER algorithm = {.pszObjId = (LPSTR)signer->signature_oid};
    if (signer->ncrypt) {
        signer->cert = CertCreateSelfSignCertificate(signer->key, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
                                                     NULL, &algorithm, NULL, NULL, &extensions);
    } else {
        CRYPT_KEY_PROV_INFO parameters = {
            .pwszContainerName = signer->container[0] ? signer->container : NULL,
            .pwszProvName = signer->provider_name[0] ? signer->provider_name : NULL,
            .dwProvType = signer->provider_type, .dwKeySpec = AT_SIGNATURE
        };
        signer->cert = CertCreateSelfSignCertificate(signer->capi, &subject, 0, &parameters,
                                                     &algorithm, NULL, NULL, &extensions);
    }
    if (!signer->cert) {
        fwprintf(stderr, L"Cannot create the local certificate (Win32 %lu).\n", GetLastError());
        signer_close(signer);
        return FALSE;
    }
    if (signer->cert->cbCertEncoded > sizeof signer->certificate.der) {
        fwprintf(stderr, L"The local certificate is too large.\n");
        signer_close(signer);
        return FALSE;
    }
    signer->certificate.size = signer->cert->cbCertEncoded;
    memcpy(signer->certificate.der, signer->cert->pbCertEncoded, signer->certificate.size);
    return TRUE;
}

static void signer_close(NttpSigner *signer)
{
    if (signer->cert)
        CertFreeCertificateContext(signer->cert);
    if (signer->capi_key)
        CryptDestroyKey(signer->capi_key);
    if (signer->capi) {
        CryptReleaseContext(signer->capi, 0);
        HCRYPTPROV stale = 0;
        if (signer->container[0])
            CryptAcquireContextW(&stale, signer->container,
                                 signer->provider_name[0] ? signer->provider_name : NULL,
                                 signer->provider_type, CRYPT_DELETEKEYSET | CRYPT_SILENT);
    }
    if (signer->key)
        NCryptFreeObject(signer->key);
    if (signer->provider)
        NCryptFreeObject(signer->provider);
    memset(signer, 0, sizeof *signer);
}

#if !defined(NTTP_NO_ATTACH)
#include "signer_attach.h"
#endif

/* Embed one signature over the file as it currently is on disk. */
static BOOL signer_sign(NttpSigner *signer, SipApi *sip, const wchar_t *path)
{
    /* The copy fallback calls this again for the temporary file; the nested call must
       not fall back once more. */
    static int depth;
    if (!signer->cert) {
        wprintf(L"  signer: no certificate was created (Win32 %lu).\n", GetLastError());
        return FALSE;
    }
    if (!signer_sip(sip)) {
        wprintf(L"  signer: cannot load the SIP entry points from crypt32.dll (Win32 %lu).\n", GetLastError());
        return FALSE;
    }
    BYTE content_der[4096], signature[8192];
    DWORD content_size = sizeof content_der, signed_size = sizeof signature;
    DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    GUID subject_type;
    HCRYPTMSG message = NULL;
    BOOL ok = FALSE;
    if (!sip->subject_guid(path, NULL, &subject_type)) {
        /* CryptSIPRetrieveSubjectGuid reports CRYPT_E_NOT_FOUND for a PE image that
           carries no certificate table yet, for example a catalog-signed system
           binary. The image is still signable, so use the well-known PE subject
           type instead of giving up. */
        static const GUID pe_image = {0xc689aab8, 0x8e78, 0x11d0,
                                      {0x8c, 0x47, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee}};
        subject_type = pe_image;
        wprintf(L"  signer: no subject type in the file (0x%08lX); using the PE type.\n", GetLastError());
    }
    /* Hand the SIP our own handle. With a file name it opens the file itself, and on a
       protected system binary that open is refused with ERROR_ACCESS_DENIED even when
       this process already holds write access. */
    HANDLE subject = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    SIP_SUBJECTINFO info = {.cbSize = sizeof info, .pgSubjectType = &subject_type,
        .hFile = subject,
        .pwsFileName = subject == INVALID_HANDLE_VALUE ? path : NULL,
        .DigestAlgorithm = {.pszObjId = (LPSTR)signer->hash_oid}, .dwEncodingType = encoding, .dwFlags = 0x10};
    union { SIP_INDIRECT_DATA entry; BYTE storage[4096]; } indirect;
    DWORD indirect_size = sizeof indirect;
    if (!sip->create(&info, &indirect_size, &indirect.entry)) {
        wprintf(L"  signer: CryptSIPCreateFromContext failed (0x%08lX), file %ls.\n", GetLastError(), path);
        if (subject != INVALID_HANDLE_VALUE)
            CloseHandle(subject);
        return FALSE;
    }
    SPC_INDIRECT_DATA_CONTENT content = {indirect.entry.Data, indirect.entry.DigestAlgorithm, indirect.entry.Digest};
    if (!CryptEncodeObjectEx(encoding, SPC_INDIRECT_DATA_OBJID, &content, 0, NULL, content_der, &content_size)) {
        wprintf(L"  signer: CryptEncodeObjectEx failed (0x%08lX).\n", GetLastError());
        return FALSE;
    }
    CMSG_SIGNER_ENCODE_INFO signer_info = {
        .cbSize = sizeof signer_info, .pCertInfo = signer->cert->pCertInfo,
        .HashAlgorithm = {.pszObjId = (LPSTR)signer->hash_oid}
    };
    if (signer->ncrypt) {
        signer_info.hNCryptKey = signer->key;
        signer_info.dwKeySpec = CERT_NCRYPT_KEY_SPEC;
    } else {
        memcpy(&signer_info.hCryptProv, &signer->capi, sizeof signer->capi);
        signer_info.dwKeySpec = AT_SIGNATURE;
    }
    CERT_BLOB encoded = {signer->cert->cbCertEncoded, signer->cert->pbCertEncoded};
    CMSG_SIGNED_ENCODE_INFO cms = {
        .cbSize = sizeof cms, .cSigners = 1, .rgSigners = &signer_info, .cCertEncoded = 1, .rgCertEncoded = &encoded
    };
    message = CryptMsgOpenToEncode(encoding, 0, CMSG_SIGNED, &cms, SPC_INDIRECT_DATA_OBJID, NULL);
    if (message && CryptMsgUpdate(message, content_der, content_size, TRUE) &&
        CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, signature, &signed_size)) {
        DWORD index = 0;
        ok = sip->put(&info, encoding, &index, signed_size, signature);
        if (!ok)
            wprintf(L"  signer: CryptSIPPutSignedDataMsg failed (0x%08lX).\n", GetLastError());
    }
    if (message)
        CryptMsgClose(message);
    if (subject != INVALID_HANDLE_VALUE)
        CloseHandle(subject);
#if !defined(NTTP_NO_ATTACH)
    if (!ok && depth == 0) {
        /* The SIP refused the file itself. Sign an identical copy in a writable folder
           and move that certificate table here; if even that fails, build one here. */
        ++depth;
        ok = signer_sign_via_copy(signer, sip, path) || signer_attach(signer, path);
        --depth;
    }
#endif
    return ok;
}

/* Drop an existing certificate table so the new signature is the only one and
   covers the modified bytes. */
static BOOL signer_strip_signature(BYTE *data, DWORD *size)
{
    if (*size < 0x60)
        return FALSE;
    uint32_t pe;
    memcpy(&pe, data + 0x3c, sizeof pe);
    if (pe > *size - 0x60 || pe < 0x40)
        return FALSE;
    uint32_t signature;
    WORD magic;
    memcpy(&signature, data + pe, sizeof signature);
    memcpy(&magic, data + pe + 24, sizeof magic);
    DWORD directory;
    if (signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        directory = pe + 24 + 0x60 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        directory = pe + 24 + 0x70 + IMAGE_DIRECTORY_ENTRY_SECURITY * 8;
    else
        return FALSE;
    if (directory + 8 > *size)
        return FALSE;
    DWORD offset, length;
    memcpy(&offset, data + directory, sizeof offset);
    memcpy(&length, data + directory + 4, sizeof length);
    if (!offset && !length)
        return TRUE;
    /* Only drop a table that ends the file; anything else is unexpected. */
    if (!length || offset < directory + 8 || offset > *size || length > *size - offset ||
        offset + length != *size)
        return FALSE;
    memset(data + directory, 0, 8);
    *size = offset;
    return TRUE;
}

/* Read the certificate of the signature already embedded in a file. */
static BOOL signer_extract(const wchar_t *path, const wchar_t *subject_name, NttpCertificate *certificate)
{
    const DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    PCCERT_CONTEXT current = NULL;
    BOOL ok = FALSE;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &store, &message, NULL))
        return FALSE;
    while ((current = CertEnumCertificatesInStore(store, current)) != NULL) {
        wchar_t subject[256];
        if (CertGetNameStringW(current, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, subject, ARRAYSIZE(subject)) <= 1 ||
            wcscmp(subject, subject_name) || current->cbCertEncoded > sizeof certificate->der)
            continue;
        certificate->size = current->cbCertEncoded;
        memcpy(certificate->der, current->pbCertEncoded, certificate->size);
        ok = TRUE;
        break;
    }
    if (current)
        CertFreeCertificateContext(current);
    if (message)
        CryptMsgClose(message);
    if (store)
        CertCloseStore(store, 0);
    (void)encoding;
    return ok;
}

/* Cryptographic check of the embedded signature; trust is a separate question. */
static BOOL signer_verify(const wchar_t *path)
{
    const DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    PCERT_INFO info = NULL;
    PCCERT_CONTEXT cert = NULL;
    DWORD count = 0, count_size = sizeof count, size = 0;
    BOOL ok = FALSE;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &store, &message, NULL) ||
        !message || !store || !CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, &count, &count_size) ||
        count != 1 || !CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &size) ||
        size < sizeof *info || size > 65536)
        goto done;
    info = malloc(size);
    if (!info || !CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, info, &size))
        goto done;
    cert = CertGetSubjectCertificateFromStore(store, encoding, info);
    ok = cert && CryptMsgControl(message, 0, CMSG_CTRL_VERIFY_SIGNATURE, cert->pCertInfo);
done:
    if (cert)
        CertFreeCertificateContext(cert);
    free(info);
    if (message)
        CryptMsgClose(message);
    if (store)
        CertCloseStore(store, 0);
    return ok;
}

static BOOL signer_remove_certificate(HCERTSTORE store, const NttpCertificate *certificate)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, certificate->der, certificate->size);
    if (!cert)
        return FALSE;
    PCCERT_CONTEXT found = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, cert, NULL);
    DWORD error = GetLastError();
    CertFreeCertificateContext(cert);
    return found ? CertDeleteCertificateFromStore(found) : error == (DWORD)CRYPT_E_NOT_FOUND;
}

/* Root and TrustedPublisher in the running system's machine store. */
static BOOL signer_live_trust(const NttpCertificate *certificate, BOOL add)
{
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    HCERTSTORE publisher = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0,
                                         CERT_SYSTEM_STORE_LOCAL_MACHINE, L"TrustedPublisher");
    BOOL ok = roots && publisher;
    if (ok && add) {
        ok = CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, certificate->der, certificate->size,
                                             CERT_STORE_ADD_NEW, NULL) ||
             GetLastError() == (DWORD)CRYPT_E_EXISTS;
        ok = ok && (CertAddEncodedCertificateToStore(publisher, X509_ASN_ENCODING, certificate->der,
                                                     certificate->size, CERT_STORE_ADD_NEW, NULL) ||
                    GetLastError() == (DWORD)CRYPT_E_EXISTS);
    } else if (ok) {
        ok = signer_remove_certificate(roots, certificate) &&
             signer_remove_certificate(publisher, certificate);
    }
    DWORD error = GetLastError();
    if (roots)
        CertCloseStore(roots, 0);
    if (publisher)
        CertCloseStore(publisher, 0);
    if (ok && add) {
        CertResyncCertificateChainEngine(HCCE_LOCAL_MACHINE);
        CertResyncCertificateChainEngine(HCCE_CURRENT_USER);
    }
    SetLastError(error);
    return ok;
}

