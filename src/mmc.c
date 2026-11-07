#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wincrypt.h>
#include <mscat.h>
#include <ncrypt.h>
#include <softpub.h>

#define MMC_RECEIPT L"SOFTWARE\\NTTimebombPatch\\MMC"
#define MMC_EMBEDDED_RECEIPT L"SOFTWARE\\NTTimebombPatch\\MMCEmbedded"
#define MMC_CAT_PREFIX L"NTTimebomb-MMC-"

typedef struct {
    DWORD size;
    BYTE der[2048];
} MmcCertificate;

typedef struct {
    wchar_t name[80];
    MmcCertificate certificate;
} MmcReceipt;

typedef struct {
    DWORD version;
    wchar_t id[33];
    BYTE original_hash[32], signed_hash[32];
    MmcCertificate certificate;
} MmcInstall;

static GUID mmc_action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
enum { MMC_CONSENT_SIGNATURE_FLAGS = 0x0807, MMC_BASE_VERIFICATION = 0x1000, MMC_PREFER_CATALOG = 0x2000 };

static BOOL mmc_expired_chain(HCERTCHAINENGINE engine, PCCERT_CONTEXT cert, HCERTSTORE store)
{
    wchar_t publisher[64], organization[64];
    if (CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, publisher, 64) <= 1 ||
        wcscmp(publisher, L"Microsoft Windows") ||
        CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, szOID_ORGANIZATION_NAME, organization, 64) <= 1 ||
        wcscmp(organization, L"Microsoft Corporation")) return FALSE;

    LPSTR code_signing = szOID_PKIX_KP_CODE_SIGNING;
    CERT_CHAIN_PARA parameters = {
        .cbSize = sizeof parameters,
        .RequestedUsage = {USAGE_MATCH_TYPE_AND, {1, &code_signing}}
    };
    PCCERT_CHAIN_CONTEXT chain = NULL;
    if (!CertGetCertificateChain(engine, cert, NULL, store, &parameters,
                                 CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &chain)) {
        wprintf(L"Cannot rebuild the MMC signer's chain (Win32 %lu).\n", GetLastError());
        return FALSE;
    }
    DWORD flags = chain->TrustStatus.dwErrorStatus;
    CERT_CHAIN_POLICY_PARA policy = {
        .cbSize = sizeof policy, .dwFlags = CERT_CHAIN_POLICY_IGNORE_NOT_TIME_VALID_FLAG
    };
    CERT_CHAIN_POLICY_STATUS result = {.cbSize = sizeof result};
    BOOL policy_ok = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_AUTHENTICODE, chain, &policy, &result);
    wprintf(L"MMC signer chain flags 0x%08lx, Authenticode policy 0x%08lx.\n",
            flags, policy_ok ? result.dwError : GetLastError());
    CertFreeCertificateChain(chain);
    return flags == CERT_TRUST_IS_NOT_TIME_VALID && policy_ok && !result.dwError;
}

static BOOL mmc_read_expired_signer(HCERTCHAINENGINE engine, const wchar_t *path)
{
    const DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    HCERTSTORE store = NULL;
    HCRYPTMSG message = NULL;
    PCCERT_CONTEXT cert = NULL;
    CERT_INFO *signer = NULL;
    DWORD count = 0, count_size = sizeof count, size = 0;
    BOOL ok = FALSE;
    /* Expired catalogs need not leave a chain in the WinVerifyTrust state. */
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &store, &message, NULL) ||
        !message || !store || !CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, &count, &count_size) ||
        count != 1 || !CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, NULL, &size) ||
        size < sizeof *signer || size > 65536) goto done;
    signer = HeapAlloc(GetProcessHeap(), 0, size);
    if (!signer || !CryptMsgGetParam(message, CMSG_SIGNER_CERT_INFO_PARAM, 0, signer, &size)) goto done;
    cert = CertGetSubjectCertificateFromStore(store, encoding, signer);
    if (cert && CryptMsgControl(message, 0, CMSG_CTRL_VERIFY_SIGNATURE, cert->pCertInfo))
        ok = mmc_expired_chain(engine, cert, store);
done:
    if (cert) CertFreeCertificateContext(cert);
    if (signer) HeapFree(GetProcessHeap(), 0, signer);
    if (message) CryptMsgClose(message);
    if (store) CertCloseStore(store, 0);
    return ok;
}

static LONG mmc_verify(WINTRUST_DATA *trust, BOOL *expiry_only)
{
    trust->cbStruct = sizeof *trust;
    trust->dwUIChoice = WTD_UI_NONE;
    trust->dwStateAction = WTD_STATEACTION_VERIFY;
    trust->dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    LONG status = WinVerifyTrust(INVALID_HANDLE_VALUE, &mmc_action, trust);
    if (status == (LONG)CERT_E_EXPIRED && expiry_only)
        *expiry_only = mmc_read_expired_signer(HCCE_LOCAL_MACHINE, trust->dwUnionChoice == WTD_CHOICE_CATALOG ?
                                              trust->pCatalog->pcwszCatalogFilePath : trust->pFile->pcwszFilePath);
    trust->dwStateAction = WTD_STATEACTION_CLOSE;
    if (trust->hWVTStateData) WinVerifyTrust(INVALID_HANDLE_VALUE, &mmc_action, trust);
    return status;
}

static BOOL mmc_expired(wchar_t *path, HANDLE file)
{
    BOOL expired = FALSE;
    WINTRUST_FILE_INFO fi = {.cbStruct = sizeof fi, .pcwszFilePath = path, .hFile = file};
    WINTRUST_DATA embedded = {.dwUnionChoice = WTD_CHOICE_FILE, .pFile = &fi};
    LONG status = mmc_verify(&embedded, &expired);
    if (status != (LONG)TRUST_E_NOSIGNATURE) {
        wprintf(L"Embedded MMC signature status 0x%08lx.\n", (unsigned long)status);
        return expired;
    }

    const wchar_t *algorithms[] = {L"SHA256", L"SHA1"};
    for (unsigned a = 0; a < ARRAYSIZE(algorithms); ++a) {
        HCATADMIN admin;
        if (!CryptCATAdminAcquireContext2(&admin, NULL, algorithms[a], NULL, 0)) continue;
        BYTE digest[64];
        DWORD size = sizeof digest;
        BOOL hash = CryptCATAdminCalcHashFromFileHandle2(admin, file, &size, digest, 0);
        HCATINFO cat = NULL;
        if (hash && size && size <= sizeof digest) {
            static const wchar_t hex[] = L"0123456789ABCDEF";
            wchar_t tag[129] = {0};
            for (DWORD i = 0; i < size; ++i) {
                tag[i*2] = hex[digest[i] >> 4];
                tag[i*2+1] = hex[digest[i] & 15];
            }
            while ((cat = CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, cat ? &cat : NULL))) {
                CATALOG_INFO info = {.cbStruct = sizeof info};
                if (!CryptCATCatalogInfoFromContext(cat, &info, 0)) continue;
                WINTRUST_CATALOG_INFO member = {
                    .cbStruct = sizeof member, .pcwszCatalogFilePath = info.wszCatalogFile,
                    .pcwszMemberTag = tag, .pcwszMemberFilePath = path, .hMemberFile = file,
                    .pbCalculatedFileHash = digest, .cbCalculatedFileHash = size, .hCatAdmin = admin
                };
                WINTRUST_DATA trust = {.dwUnionChoice = WTD_CHOICE_CATALOG, .pCatalog = &member};
                BOOL match = FALSE;
                status = mmc_verify(&trust, &match);
                wprintf(L"MMC catalog signature status 0x%08lx for %ls.\n", (unsigned long)status, info.wszCatalogFile);
                expired |= match;
                if (!status) break;
            }
        }
        if (cat) CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        CryptCATAdminReleaseContext(admin, 0);
        if (!status) return FALSE;
    }
    return expired;
}

/* The system's signature-info query also sees competing catalog entries. */
static BOOL mmc_selected(wchar_t *path, HANDLE file, DWORD flags, const MmcCertificate *certificate)
{
    typedef HRESULT (WINAPI *SignatureInfo)(LPCWSTR, HANDLE, DWORD, void *, PCCERT_CONTEXT *, HANDLE *);
    SignatureInfo query = (SignatureInfo)GetProcAddress(GetModuleHandleW(L"wintrust.dll"), "WTGetSignatureInfo");
    if (!query) return FALSE;
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
    HANDLE state = NULL;
    PCCERT_CONTEXT cert = NULL;
    HRESULT result = query(path, file, flags, &info, &cert, &state);
    BOOL trusted = info.state == 6 || ((flags & MMC_BASE_VERIFICATION) && info.state == 5);
    BOOL valid = SUCCEEDED(result) && trusted && info.type == 1 && !info.os_binary && cert &&
        cert->cbCertEncoded == certificate->size && !memcmp(cert->pbCertEncoded, certificate->der, certificate->size);
    wprintf(L"MMC signature query 0x%04lx returned 0x%08lx, state %lu, type %lu.\n",
            flags, (unsigned long)result, info.state, info.type);
    if (cert) CertFreeCertificateContext(cert);
    if (state) {
        WINTRUST_DATA close = {.cbStruct = sizeof close, .dwStateAction = WTD_STATEACTION_CLOSE, .hWVTStateData = state};
        WinVerifyTrust(INVALID_HANDLE_VALUE, &mmc_action, &close);
    }
    return valid;
}

static BOOL mmc_sign(const wchar_t *path, MmcCertificate *certificate)
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;
    PCCERT_CONTEXT cert = NULL;
    HCRYPTMSG signed_msg = NULL;
    BYTE content_der[4096], signature[8192], name[128], usage[64];
    GUID subject_type;
    DWORD content_size = sizeof content_der, signed_size = sizeof signature;
    DWORD name_size = sizeof name, usage_size = sizeof usage;
    DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, bits = 2048;
    BOOL ok = FALSE;
    if (NCryptOpenStorageProvider(&provider, MS_KEY_STORAGE_PROVIDER, 0) ||
        NCryptCreatePersistedKey(provider, &key, NCRYPT_RSA_ALGORITHM, NULL, 0, 0) ||
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bits, sizeof bits, 0) ||
        NCryptFinalizeKey(key, 0)) goto done;
    LPSTR oid = szOID_PKIX_KP_CODE_SIGNING;
    CERT_ENHKEY_USAGE eku = {1, &oid};
    if (!CertStrToNameW(X509_ASN_ENCODING, L"CN=NT Timebomb Patch local MMC", CERT_X500_NAME_STR,
                        NULL, name, &name_size, NULL) ||
        !CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku, 0, NULL, usage, &usage_size))
        goto done;
    CERT_NAME_BLOB subject = {name_size, name};
    CERT_EXTENSION extension = {.pszObjId = szOID_ENHANCED_KEY_USAGE, .Value = {usage_size, usage}};
    CERT_EXTENSIONS extensions = {1, &extension};
    CRYPT_ALGORITHM_IDENTIFIER algorithm = {.pszObjId = szOID_RSA_SHA256RSA};
    cert = CertCreateSelfSignCertificate(key, &subject, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
                                         NULL, &algorithm, NULL, NULL, &extensions);
    if (!cert || cert->cbCertEncoded > sizeof certificate->der ||
        !CryptSIPRetrieveSubjectGuid(path, NULL, &subject_type)) goto done;
    SIP_SUBJECTINFO sip = {.cbSize=sizeof sip, .pgSubjectType=&subject_type, .hFile=INVALID_HANDLE_VALUE,
        .pwsFileName=path, .DigestAlgorithm={.pszObjId=szOID_NIST_sha256}, .dwEncodingType=encoding, .dwFlags=0x10};
    union { SIP_INDIRECT_DATA entry; BYTE storage[4096]; } indirect;
    DWORD indirect_size=sizeof indirect;
    if (!CryptSIPCreateIndirectData(&sip,&indirect_size,&indirect.entry)) goto done;
    SPC_INDIRECT_DATA_CONTENT content={indirect.entry.Data,indirect.entry.DigestAlgorithm,indirect.entry.Digest};
    if (!CryptEncodeObjectEx(encoding, SPC_INDIRECT_DATA_OBJID, &content, 0, NULL,
                             content_der, &content_size)) goto done;
    CMSG_SIGNER_ENCODE_INFO signer = {
        .cbSize = sizeof signer, .pCertInfo = cert->pCertInfo, .hNCryptKey = key, .dwKeySpec = CERT_NCRYPT_KEY_SPEC,
        .HashAlgorithm = {.pszObjId = szOID_NIST_sha256}
    };
    CERT_BLOB encoded = {cert->cbCertEncoded, cert->pbCertEncoded};
    CMSG_SIGNED_ENCODE_INFO cms = {
        .cbSize = sizeof cms, .cSigners = 1, .rgSigners = &signer, .cCertEncoded = 1, .rgCertEncoded = &encoded
    };
    signed_msg = CryptMsgOpenToEncode(encoding, 0, CMSG_SIGNED, &cms, SPC_INDIRECT_DATA_OBJID, NULL);
    if (!signed_msg || !CryptMsgUpdate(signed_msg, content_der, content_size, TRUE) ||
        !CryptMsgGetParam(signed_msg, CMSG_CONTENT_PARAM, 0, signature, &signed_size)) goto done;
    DWORD index = 0;
    ok = CryptSIPPutSignedDataMsg(&sip, encoding, &index, signed_size, signature);
    if (ok) {
        certificate->size = cert->cbCertEncoded;
        memcpy(certificate->der, cert->pbCertEncoded, certificate->size);
    }
done:
    if (signed_msg) CryptMsgClose(signed_msg);
    if (cert) CertFreeCertificateContext(cert);
    if (key && NCryptFreeObject(key)) ok = FALSE;
    if (provider) NCryptFreeObject(provider);
    return ok;
}

static BOOL mmc_remove_cert(HCERTSTORE store, const MmcCertificate *certificate)
{
    PCCERT_CONTEXT cert = CertCreateCertificateContext(X509_ASN_ENCODING, certificate->der, certificate->size);
    if (!cert) return FALSE;
    PCCERT_CONTEXT found = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, cert, NULL);
    DWORD error = GetLastError();
    CertFreeCertificateContext(cert);
    return found ? CertDeleteCertificateFromStore(found) : error == (DWORD)CRYPT_E_NOT_FOUND;
}

static BOOL mmc_publisher(const MmcCertificate *certificate, BOOL add)
{
    HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_REGISTRY_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE, L"TrustedPublisher");
    if (!store) return FALSE;
    BOOL ok = add ? CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, certificate->der,
                        certificate->size, CERT_STORE_ADD_NEW, NULL) : mmc_remove_cert(store, certificate);
    DWORD error = GetLastError();
    CertCloseStore(store, 0);
    if (!ok) SetLastError(error);
    return ok;
}

static BOOL mmc_certificate_valid(const MmcCertificate *certificate)
{
    return certificate->size && certificate->size <= sizeof certificate->der;
}

static BOOL mmc_legacy_restore(HCERTSTORE roots)
{
    MmcReceipt receipt = {0};
    DWORD size = sizeof receipt;
    LSTATUS error = RegGetValueW(HKEY_LOCAL_MACHINE, MMC_RECEIPT, L"Receipt",
                                RRF_RT_REG_BINARY, NULL, &receipt, &size);
    if (error == ERROR_FILE_NOT_FOUND) {
        wprintf(L"No MMC exception found.\n");
        return TRUE;
    }
    if (error || size != sizeof receipt || !mmc_certificate_valid(&receipt.certificate) ||
        !wmemchr(receipt.name, 0, ARRAYSIZE(receipt.name)) ||
        wcsncmp(receipt.name, MMC_CAT_PREFIX, ARRAYSIZE(MMC_CAT_PREFIX)-1) ||
        wcspbrk(receipt.name, L"\\/:")) return FALSE;
    HCATADMIN admin;
    if (!CryptCATAdminAcquireContext2(&admin, NULL, L"SHA256", NULL, 0)) return FALSE;
    BOOL removed = CryptCATAdminRemoveCatalog(admin, receipt.name, 0);
    DWORD status = GetLastError();
    CryptCATAdminReleaseContext(admin, 0);
    return (removed || status == ERROR_FILE_NOT_FOUND || status == ERROR_NOT_FOUND) &&
        mmc_remove_cert(roots, &receipt.certificate) &&
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, MMC_RECEIPT) == ERROR_SUCCESS;
}

static BOOL mmc_privilege(const wchar_t *name)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token)) return FALSE;
    TOKEN_PRIVILEGES privileges = {.PrivilegeCount = 1};
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = LookupPrivilegeValueW(NULL, name, &privileges.Privileges[0].Luid) &&
        AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static HANDLE mmc_open(const wchar_t *path, DWORD access, DWORD sharing, DWORD disposition)
{
    HANDLE file = CreateFileW(path, access, sharing, NULL, disposition,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (file == INVALID_HANDLE_VALUE) return file;
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) return file;
    CloseHandle(file);
    SetLastError(ERROR_INVALID_DATA);
    return INVALID_HANDLE_VALUE;
}

static BOOL mmc_rename(HANDLE file, const wchar_t *destination)
{
    union {
        FILE_RENAME_INFO info;
        BYTE bytes[sizeof(FILE_RENAME_INFO) + MAX_PATH * sizeof(wchar_t)];
    } rename = {0};
    rename.info.FileNameLength = (DWORD)(wcslen(destination) * sizeof(wchar_t));
    memcpy(rename.info.FileName, destination, rename.info.FileNameLength);
    return SetFileInformationByHandle(file, FileRenameInfo, &rename,
                                      sizeof(FILE_RENAME_INFO) + rename.info.FileNameLength);
}

static BYTE *mmc_read(HANDLE file, DWORD *size)
{
    LARGE_INTEGER length, start = {0};
    if (!GetFileSizeEx(file, &length) || length.QuadPart <= 0 || length.QuadPart > 32*1024*1024 ||
        !SetFilePointerEx(file, start, NULL, FILE_BEGIN)) return NULL;
    BYTE *data = malloc((size_t)length.QuadPart);
    if (data && ReadFile(file, data, (DWORD)length.QuadPart, size, NULL) && *size == (DWORD)length.QuadPart)
        return data;
    free(data);
    return NULL;
}

static BOOL mmc_sha256(BYTE *data, DWORD size, BYTE digest[32])
{
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0)) return FALSE;
    BOOL ok = !BCryptHash(algorithm, NULL, 0, data, size, digest, 32);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static BOOL mmc_file_hash(HANDLE file, BYTE digest[32])
{
    DWORD size;
    BYTE *data = mmc_read(file, &size);
    BOOL ok = data && mmc_sha256(data, size, digest);
    free(data);
    return ok;
}

static BOOL mmc_copy_metadata(HANDLE from, HANDLE to)
{
    FILE_BASIC_INFO info;
    SECURITY_INFORMATION flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!GetFileInformationByHandleEx(from, FileBasicInfo, &info, sizeof info) ||
        GetSecurityInfo(from, SE_FILE_OBJECT, flags, NULL, NULL, NULL, NULL, &descriptor) != ERROR_SUCCESS)
        return FALSE;
    SECURITY_DESCRIPTOR_CONTROL control;
    DWORD revision;
    BOOL ok = GetSecurityDescriptorControl(descriptor, &control, &revision) &&
        SetKernelObjectSecurity(to, flags | ((control & SE_DACL_PROTECTED) ?
            PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION), descriptor) &&
        SetFileInformationByHandle(to, FileBasicInfo, &info, sizeof info);
    LocalFree(descriptor);
    return ok;
}

static BOOL mmc_stage(HANDLE original, const wchar_t *path, MmcInstall *record)
{
    DWORD size;
    BYTE *data = mmc_read(original, &size);
    if (!data) return FALSE;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS pe;
    BOOL supported = FALSE;
    if (size >= sizeof dos + sizeof pe) {
        memcpy(&dos, data, sizeof dos);
        if (dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew >= (LONG)sizeof dos &&
            (DWORD)dos.e_lfanew <= size - sizeof pe) {
            memcpy(&pe, data + dos.e_lfanew, sizeof pe);
            supported = pe.Signature == IMAGE_NT_SIGNATURE &&
                pe.FileHeader.SizeOfOptionalHeader >= sizeof pe.OptionalHeader &&
                pe.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC &&
                pe.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY &&
                !pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress &&
                !pe.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size &&
                !(pe.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
        }
    }
    if (!supported) {
        fwprintf(stderr, L"Unsupported MMC layout. An unsigned PE certificate table is required.\n");
        free(data);
        return FALSE;
    }
    HANDLE output = mmc_open(path, GENERIC_WRITE, 0, CREATE_NEW);
    DWORD written;
    /* Distinguish the PE signing hash from the expired Microsoft catalog. */
    static const char overlay[] = "NTTPMMC1";
    BOOL ok = output != INVALID_HANDLE_VALUE && mmc_sha256(data, size, record->original_hash) &&
        WriteFile(output, data, size, &written, NULL) && written == size &&
        WriteFile(output, overlay, sizeof overlay-1, &written, NULL) && written == sizeof overlay-1;
    free(data);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    if (!ok || !mmc_sign(path, &record->certificate)) return FALSE;
    output = mmc_open(path, GENERIC_READ | GENERIC_WRITE | WRITE_OWNER | WRITE_DAC, 0, OPEN_EXISTING);
    ok = output != INVALID_HANDLE_VALUE && mmc_file_hash(output, record->signed_hash) &&
        FlushFileBuffers(output) && mmc_copy_metadata(original, output);
    if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
    return ok;
}

static BOOL mmc_publish(const wchar_t *target, const wchar_t *backup, const wchar_t *stage, const MmcInstall *record)
{
    HANDLE original = mmc_open(target, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING);
    HANDLE pending = mmc_open(stage, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING);
    BYTE hash[32];
    BOOL saved = original != INVALID_HANDLE_VALUE && pending != INVALID_HANDLE_VALUE &&
        mmc_file_hash(original, hash) && !memcmp(hash, record->original_hash, sizeof hash) &&
        mmc_file_hash(pending, hash) && !memcmp(hash, record->signed_hash, sizeof hash) && mmc_rename(original, backup);
    BOOL ok = saved && mmc_rename(pending, target);
    if (saved && !ok && !mmc_rename(original, target))
        fwprintf(stderr, L"Original MMC retained at %ls. Run /mmc-restore.\n", backup);
    if (pending != INVALID_HANDLE_VALUE) CloseHandle(pending);
    if (original != INVALID_HANDLE_VALUE) CloseHandle(original);
    return ok;
}

static BOOL mmc_restore_file(const wchar_t *target, const wchar_t *backup, const wchar_t *stage,
                             const MmcInstall *record)
{
    BYTE hash[32];
    HANDLE read_only = mmc_open(target, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (read_only != INVALID_HANDLE_VALUE) {
        BOOL original_present = mmc_file_hash(read_only, hash) && !memcmp(hash, record->original_hash, sizeof hash);
        CloseHandle(read_only);
        if (original_present) return TRUE;
    }
    HANDLE current = mmc_open(target, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING);
    DWORD error = GetLastError();
    BOOL present = current != INVALID_HANDLE_VALUE;
    BOOL readable = present && mmc_file_hash(current, hash);
    BOOL ok = readable && !memcmp(hash, record->original_hash, sizeof hash);
    BOOL can_restore = (readable && !memcmp(hash, record->signed_hash, sizeof hash)) ||
        (!present && error == ERROR_FILE_NOT_FOUND);
    if (!ok && can_restore) {
        HANDLE original = mmc_open(backup, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING);
        BOOL found = original != INVALID_HANDLE_VALUE && mmc_file_hash(original, hash) &&
            !memcmp(hash, record->original_hash, sizeof hash);
        BOOL parked = found && (!present || mmc_rename(current, stage));
        ok = parked && mmc_rename(original, target);
        if (parked && !ok && present) mmc_rename(current, target);
        if (original != INVALID_HANDLE_VALUE) CloseHandle(original);
    }
    if (present) CloseHandle(current);
    return ok;
}

typedef struct {
    wchar_t dir[MAX_PATH], original[MAX_PATH], stage[MAX_PATH];
} MmcPaths;

static BOOL mmc_paths(const wchar_t *id, MmcPaths *paths)
{
    wchar_t windows[MAX_PATH];
    UINT length = GetWindowsDirectoryW(windows, ARRAYSIZE(windows));
    return length && length < ARRAYSIZE(windows) &&
        swprintf(paths->dir, ARRAYSIZE(paths->dir), L"%ls\\NTTP-MMC-%ls", windows, id) > 0 &&
        swprintf(paths->original, ARRAYSIZE(paths->original), L"%ls\\original.exe", paths->dir) > 0 &&
        swprintf(paths->stage, ARRAYSIZE(paths->stage), L"%ls\\pending.exe", paths->dir) > 0;
}

static BOOL mmc_journal_valid(const MmcInstall *record)
{
    if ((record->version != 1 && record->version != 2) || record->id[32] ||
        !mmc_certificate_valid(&record->certificate)) return FALSE;
    return wcsspn(record->id, L"0123456789abcdef") == 32;
}

static BOOL mmc_stage_directory(const wchar_t *dir)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, NULL)) return FALSE;
    SECURITY_ATTRIBUTES attributes = {sizeof attributes, descriptor, FALSE};
    BOOL ok = CreateDirectoryW(dir, &attributes);
    LocalFree(descriptor);
    return ok;
}

static void mmc_cleanup_stage(const MmcPaths *paths)
{
    HANDLE stage = mmc_open(paths->stage, DELETE | FILE_WRITE_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_DELETE, OPEN_EXISTING);
    if (stage != INVALID_HANDLE_VALUE) {
        FILE_BASIC_INFO attributes = {.FileAttributes = FILE_ATTRIBUTE_NORMAL};
        FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE};
        SetFileInformationByHandle(stage, FileBasicInfo, &attributes, sizeof attributes);
        SetFileInformationByHandle(stage, FileDispositionInfo, &disposition, sizeof disposition);
        CloseHandle(stage);
    }
    RemoveDirectoryW(paths->dir);
}

static BOOL mmc_save_journal(const MmcInstall *record)
{
    HKEY key = NULL;
    DWORD disposition;
    LSTATUS error = RegCreateKeyExW(HKEY_LOCAL_MACHINE, MMC_EMBEDDED_RECEIPT, 0, NULL, 0, KEY_QUERY_VALUE | KEY_SET_VALUE,
                                    NULL, &key, &disposition);
    if (error) return FALSE;
    DWORD old_size = 0;
    BOOL empty = disposition == REG_CREATED_NEW_KEY ||
        RegQueryValueExW(key, L"Receipt", NULL, NULL, NULL, &old_size) == ERROR_FILE_NOT_FOUND;
    BOOL ok = empty && RegSetValueExW(key, L"Receipt", 0, REG_BINARY, (const BYTE *)record,
                                      sizeof *record) == ERROR_SUCCESS && RegFlushKey(key) == ERROR_SUCCESS;
    RegCloseKey(key);
    if (empty && !ok) RegDeleteKeyW(HKEY_LOCAL_MACHINE, MMC_EMBEDDED_RECEIPT);
    return ok;
}

static BOOL mmc_check_path(wchar_t *path, const MmcCertificate *certificate)
{
    static const DWORD consent_modes[] = {
        MMC_CONSENT_SIGNATURE_FLAGS,
        MMC_CONSENT_SIGNATURE_FLAGS | MMC_BASE_VERIFICATION,
        MMC_CONSENT_SIGNATURE_FLAGS | MMC_PREFER_CATALOG,
        MMC_CONSENT_SIGNATURE_FLAGS | MMC_PREFER_CATALOG | MMC_BASE_VERIFICATION,
    };
    HANDLE file = mmc_open(path, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = TRUE;
    for (unsigned i = 0; i < ARRAYSIZE(consent_modes); ++i)
        ok &= mmc_selected(path, file, consent_modes[i], certificate);
    CloseHandle(file);
    return ok;
}

static BOOL mmc_rollback(const wchar_t *target, const MmcPaths *paths, const MmcInstall *record, HCERTSTORE roots)
{
    if (!mmc_restore_file(target, paths->original, paths->stage, record) ||
        (record->version == 2 && !mmc_publisher(&record->certificate, FALSE)) ||
        !mmc_remove_cert(roots, &record->certificate) ||
        RegDeleteKeyW(HKEY_LOCAL_MACHINE, MMC_EMBEDDED_RECEIPT) != ERROR_SUCCESS) {
        fwprintf(stderr, L"MMC rollback is incomplete. Keep %ls and retry /mmc-restore.\n", paths->dir);
        return FALSE;
    }
    mmc_cleanup_stage(paths);
    return TRUE;
}

static BOOL mmc_run(BOOL restore, HCERTSTORE roots)
{
    wchar_t target[MAX_PATH];
    UINT length = GetSystemDirectoryW(target, ARRAYSIZE(target));
    if (!length || length >= ARRAYSIZE(target) || length + ARRAYSIZE(L"\\mmc.exe") > ARRAYSIZE(target)) return FALSE;
    wcscat(target, L"\\mmc.exe");

    MmcInstall record = {.version = 2};
    MmcPaths paths;
    DWORD size = sizeof record;
    LSTATUS status = RegGetValueW(HKEY_LOCAL_MACHINE, MMC_EMBEDDED_RECEIPT, L"Receipt",
                                  RRF_RT_REG_BINARY, NULL, &record, &size);
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND) return FALSE;
    if (restore && status == ERROR_FILE_NOT_FOUND) return mmc_legacy_restore(roots);
    if (!restore && (status == ERROR_SUCCESS ||
        RegGetValueW(HKEY_LOCAL_MACHINE, MMC_RECEIPT, L"Receipt", RRF_RT_REG_BINARY,
                      NULL, NULL, &(DWORD){0}) == ERROR_SUCCESS)) {
        fwprintf(stderr, L"Run /mmc-restore before applying a new MMC exception.\n");
        return FALSE;
    }
    if (!mmc_privilege(L"SeBackupPrivilege") || !mmc_privilege(L"SeRestorePrivilege")) {
        fwprintf(stderr, L"MMC requires backup and restore privileges. Use an elevated administrator or SYSTEM prompt.\n");
        return FALSE;
    }
    if (restore) {
        if (size != sizeof record || !mmc_journal_valid(&record) || !mmc_paths(record.id, &paths)) return FALSE;
        DWORD attrs = GetFileAttributesW(paths.dir);
        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY) ||
            (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return FALSE;
        if (!mmc_rollback(target, &paths, &record, roots)) return FALSE;
        wprintf(L"Restored the original MMC and removed the local certificate.\n");
        return TRUE;
    }
    HANDLE file = mmc_open(target, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = mmc_expired(target, file);
    if (!ok) fwprintf(stderr, L"Could not prove that an original Microsoft MMC signature fails solely on expiry.\n");
    BYTE random[16];
    if (ok) ok = !BCryptGenRandom(NULL, random, sizeof random, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (ok) for (unsigned i = 0; i < sizeof random; ++i) swprintf(record.id + i*2, 3, L"%02x", random[i]);
    BOOL staged = ok && mmc_paths(record.id, &paths) && mmc_stage_directory(paths.dir);
    ok = staged && mmc_stage(file, paths.stage, &record);
    CloseHandle(file);
    if (!ok || !mmc_save_journal(&record)) {
        if (staged) mmc_cleanup_stage(&paths);
        return FALSE;
    }

    BOOL trusted = CertAddEncodedCertificateToStore(roots, X509_ASN_ENCODING, record.certificate.der,
                                                    record.certificate.size, CERT_STORE_ADD_NEW, NULL) &&
        mmc_publisher(&record.certificate, TRUE);
    if (trusted) {
        CertResyncCertificateChainEngine(HCCE_LOCAL_MACHINE);
        CertResyncCertificateChainEngine(HCCE_CURRENT_USER);
    }
    if (!trusted)
        fwprintf(stderr, L"Cannot install the local MMC certificate (Win32 %lu).\n", GetLastError());
    BOOL verified = trusted && mmc_check_path(paths.stage, &record.certificate);
    BOOL published = verified && mmc_publish(target, paths.original, paths.stage, &record);
    if (verified && !published)
        fwprintf(stderr, L"Cannot publish MMC. Close any MMC consoles and check access to %ls.\n", target);
    if (published && mmc_check_path(target, &record.certificate)) {
        wprintf(L"Verified the embedded MMC signature and local publisher trust. Original MMC retained at %ls.\n", paths.original);
        return TRUE;
    }
    if (mmc_rollback(target, &paths, &record, roots))
        fwprintf(stderr, L"MMC verification or publication failed. Original MMC and trust settings were restored.\n");
    return FALSE;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc != 2 || (_wcsicmp(argv[1], L"/mmc") && _wcsicmp(argv[1], L"/mmc-restore"))) {
        fwprintf(stderr, L"Usage: nttimebomb /mmc or nttimebomb /mmc-restore from the running test Windows.\n");
        return 2;
    }
    BOOL restore = !_wcsicmp(argv[1], L"/mmc-restore");
    BOOL wow = FALSE;
    HKEY pe = NULL;
    if (!IsWow64Process(GetCurrentProcess(), &wow) || wow ||
        RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\MiniNT", 0, KEY_READ, &pe) == ERROR_SUCCESS) {
        if (pe) RegCloseKey(pe);
        fwprintf(stderr, L"Use the native executable inside the running Windows installation.\n");
        return 2;
    }
    typedef BOOL (WINAPI *OobeComplete)(PBOOL);
    OobeComplete oobe_complete = (OobeComplete)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "OOBEComplete");
    BOOL complete = FALSE;
    if (!restore && oobe_complete && (!oobe_complete(&complete) || !complete)) {
        fwprintf(stderr, L"Complete OOBE and sign in before running /mmc.\n");
        return 2;
    }
    BYTE administrators[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof administrators;
    BOOL elevated = FALSE;
    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, administrators, &sid_size) ||
        !CheckTokenMembership(NULL, administrators, &elevated) || !elevated) {
        fwprintf(stderr, L"Open an elevated command prompt inside the test Windows.\n");
        return 2;
    }
    HANDLE mutex = CreateMutexW(NULL, FALSE, L"Global\\NTTimebombPatch-MMC");
    DWORD lock = mutex ? WaitForSingleObject(mutex, 0) : WAIT_FAILED;
    if (lock != WAIT_OBJECT_0 && lock != WAIT_ABANDONED) {
        if (mutex) CloseHandle(mutex);
        fwprintf(stderr, L"MMC operation is busy.\n");
        return 1;
    }
    HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
                                     CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, L"ROOT");
    BOOL ok = roots && mmc_run(restore, roots);
    if (!ok) fwprintf(stderr, L"MMC operation did not complete.\n");
    if (roots) CertCloseStore(roots, 0);
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    return ok ? 0 : 1;
}
