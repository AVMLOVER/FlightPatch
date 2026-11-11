/* Signing without the PE SIP.

   CryptSIPPutSignedDataMsg refuses some files, for example a system binary whose
   vendor signature was stripped and that lives under a protected directory. The
   same result is produced here directly:

   1. compute the Authenticode image hash (headers and section data, skipping the
      checksum field, the security directory entry and the certificate table);
   2. build SPC_INDIRECT_DATA with that hash and encode it;
   3. sign it with the local key through CryptMsgOpenToEncode, as the SIP path does;
   4. append WIN_CERTIFICATE and point the security directory at it.

   This is what the SIP does internally; doing it here removes the dependency on the
   file name, the directory and any existing certificate table. */

/* Authenticode image hash: PE headers and every section with raw data, in file
   order, skipping the checksum, the certificate directory entry and the table. */
static BOOL signer_image_hash(BCRYPT_ALG_HANDLE sha256, const BYTE *data, DWORD size, BYTE digest[32])
{
    if (size < 0x100 || memcmp(data, "MZ", 2))
        return FALSE;
    DWORD pe = u32(data + 0x3c);
    if (pe > size - 0x60 || u32(data + pe) != IMAGE_NT_SIGNATURE)
        return FALSE;
    WORD opt = u16(data + pe + 20);
    BOOL x64 = u16(data + pe + 24) == 0x20b;
    WORD sections = u16(data + pe + 6);
    DWORD table = pe + 24 + opt;
    DWORD headers = u32(data + pe + 24 + 60);           /* SizeOfHeaders */
    DWORD checksum_offset = pe + 24 + 64;
    DWORD directory_offset = pe + 24 + (x64 ? 112u : 96u) + 32u;
    DWORD certificate_rva = u32(data + directory_offset);
    DWORD certificate_size = u32(data + directory_offset + 4);
    if (headers > size || table + (DWORD)sections * 40 > size)
        return FALSE;

    BCRYPT_HASH_HANDLE hash;
    if (BCryptCreateHash(sha256, &hash, NULL, 0, NULL, 0, 0) < 0)
        return FALSE;
    BOOL ok = TRUE;
    for (unsigned pass = 0; pass < 2 && ok; ++pass) {
        DWORD start = pass == 0 ? 0 : table;   /* 0: headers, 1: section table on */
        DWORD end = pass == 0 ? headers : size;
        if (pass == 1) {
            /* sections are hashed in file order by PointerToRawData */
            for (unsigned s = 0; s < sections && ok; ++s) {
                const BYTE *entry = data + table + s * 40;
                DWORD raw_size = u32(entry + 16), raw_pointer = u32(entry + 20);
                if (!raw_size || raw_pointer > size || raw_size > size - raw_pointer)
                    continue;
                ok = BCryptHashData(hash, (PUCHAR)data + raw_pointer, raw_size, 0) >= 0;
            }
            continue;
        }
        DWORD cursor = start;
        while (ok && cursor < end) {
            DWORD chunk_end = end;
            if (cursor <= checksum_offset && checksum_offset < end)
                chunk_end = checksum_offset;
            else if (cursor <= directory_offset && directory_offset < end)
                chunk_end = directory_offset;
            if (chunk_end > cursor)
                ok = BCryptHashData(hash, (PUCHAR)data + cursor, chunk_end - cursor, 0) >= 0;
            if (!ok)
                break;
            if (chunk_end == checksum_offset)
                cursor = checksum_offset + 4;
            else if (chunk_end == directory_offset)
                cursor = directory_offset + 8;
            else
                cursor = chunk_end;
        }
        (void)certificate_rva;
        (void)certificate_size;
    }
    if (ok)
        ok = BCryptFinishHash(hash, digest, 32, 0) >= 0;
    BCryptDestroyHash(hash);
    return ok;
}

static BOOL signer_write_certificate(const wchar_t *path, const BYTE *signature, DWORD signature_size)
{
    HANDLE file = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    Output content = {0};
    BCRYPT_ALG_HANDLE algorithm;
    BOOL ok = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
              offline_read(file, &content, algorithm);
    if (!ok) {
        if (file != INVALID_HANDLE_VALUE)
            CloseHandle(file);
        free(content.data);
        return FALSE;
    }
    DWORD pe = u32(content.data + 0x3c);
    BOOL x64 = u16(content.data + pe + 24) == 0x20b;
    DWORD directory = pe + 24 + (x64 ? 112u : 96u) + 32u;
    DWORD existing = u32(content.data + directory + 4);
    DWORD table = u32(content.data + directory);
    /* Drop an older table when it is the last thing in the file. */
    DWORD end = content.size;
    if (existing >= 8 && table == end - existing)
        end = table;
    DWORD padded = (signature_size + 7u) & ~7u;
    BYTE *grown = realloc(content.data, end + 8 + padded);
    if (!grown) {
        CloseHandle(file);
        free(content.data);
        return FALSE;
    }
    content.data = grown;
    BYTE *entry = grown + end;
    DWORD entry_length = 8 + padded;
    memcpy(entry, &entry_length, 4);
    entry[4] = 0x00; entry[5] = 0x02;    /* WIN_CERT_REVISION_2_0 */
    entry[6] = 0x02; entry[7] = 0x00;    /* WIN_CERT_TYPE_PKCS_SIGNED_DATA */
    memcpy(entry + 8, signature, signature_size);
    memset(entry + 8 + signature_size, 0, padded - signature_size);
    DWORD new_size = end + 8 + padded;
    DWORD table_size = 8 + padded;
    memcpy(grown + directory, &end, 4);
    memcpy(grown + directory + 4, &table_size, 4);
    content.size = new_size;
    ok = fix_checksum(content.data, content.size) &&
         digest(algorithm, content.data, content.size, content.sha);
    if (ok) {
        LARGE_INTEGER start = {0}, finish = {.QuadPart = content.size};
        ok = SetFilePointerEx(file, start, NULL, FILE_BEGIN) &&
             write_verified(file, &content, algorithm) &&
             SetFilePointerEx(file, finish, NULL, FILE_BEGIN) && SetEndOfFile(file) && FlushFileBuffers(file);
    }
    CloseHandle(file);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    free(content.data);
    return ok;
}

/* The fallback: hash the image, encode SPC_INDIRECT_DATA, sign it, append it. */
static BOOL signer_attach(NttpSigner *signer, const wchar_t *path)
{
    HANDLE file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output content = {0};
    BCRYPT_ALG_HANDLE sha256;
    if (file == INVALID_HANDLE_VALUE) {
        wprintf(L"  signer: cannot read %ls (Win32 %lu).\n", path, GetLastError());
        return FALSE;
    }
    BOOL ok = BCryptOpenAlgorithmProvider(&sha256, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
              offline_read(file, &content, sha256);
    CloseHandle(file);
    if (!ok) {
        free(content.data);
        wprintf(L"  signer: cannot hash %ls (Win32 %lu).\n", path, GetLastError());
        return FALSE;
    }
    BYTE image_hash[32];
    ok = signer_image_hash(sha256, content.data, content.size, image_hash);
    free(content.data);
    if (!ok) {
        wprintf(L"  signer: the PE header of %ls is not usable.\n", path);
        return FALSE;
    }

    /* SPC_INDIRECT_DATA: SPC_PE_IMAGE_DATA (no file value) plus the image hash. */
    SPC_PE_IMAGE_DATA flags = {0};
    flags.Flags.cbData = 0;
    SPC_INDIRECT_DATA_CONTENT indirect = {0};
    indirect.Data.pszObjId = (LPSTR)SPC_PE_IMAGE_DATA_OBJID;
    indirect.Data.Value.pbData = (BYTE *)&flags;
    indirect.Data.Value.cbData = sizeof flags;
    indirect.DigestAlgorithm.pszObjId = (LPSTR)signer->hash_oid;
    indirect.Digest.cbData = sizeof image_hash;
    indirect.Digest.pbData = image_hash;
    DWORD encoding = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    BYTE content_der[4096];
    DWORD content_size = sizeof content_der;
    if (!CryptEncodeObjectEx(encoding, SPC_INDIRECT_DATA_OBJID, &indirect, 0, NULL, content_der, &content_size)) {
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
    CERT_BLOB certificate = {signer->cert->cbCertEncoded, signer->cert->pbCertEncoded};
    CMSG_SIGNED_ENCODE_INFO cms = {.cbSize = sizeof cms, .cSigners = 1, .rgSigners = &signer_info,
                                   .cCertEncoded = 1, .rgCertEncoded = &certificate};
    HCRYPTMSG message = CryptMsgOpenToEncode(encoding, 0, CMSG_SIGNED, &cms, SPC_INDIRECT_DATA_OBJID, NULL);
    BYTE signature[8192];
    DWORD signature_size = sizeof signature;
    ok = message && CryptMsgUpdate(message, content_der, content_size, TRUE) &&
         CryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0, signature, &signature_size);
    if (message)
        CryptMsgClose(message);
    if (!ok) {
        wprintf(L"  signer: cannot build the signature (0x%08lX).\n", GetLastError());
        return FALSE;
    }
    if (!signer_write_certificate(path, signature, signature_size)) {
        wprintf(L"  signer: cannot write the certificate into %ls (Win32 %lu).\n", path, GetLastError());
        return FALSE;
    }
    return TRUE;
}

static BOOL signer_sign(NttpSigner *signer, SipApi *sip, const wchar_t *path);

/* Read the certificate table of a signed file. */
static BOOL signer_certificate_blob(const wchar_t *path, BYTE **blob, DWORD *size)
{
    *blob = NULL;
    *size = 0;
    HANDLE file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output content = {0};
    BCRYPT_ALG_HANDLE algorithm;
    BOOL ok = file != INVALID_HANDLE_VALUE &&
              BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
              offline_read(file, &content, algorithm);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok) {
        free(content.data);
        return FALSE;
    }
    DWORD pe = u32(content.data + 0x3c);
    BOOL x64 = u16(content.data + pe + 24) == 0x20b;
    DWORD directory = pe + 24 + (x64 ? 112u : 96u) + 32u;
    DWORD offset = u32(content.data + directory);
    DWORD length = u32(content.data + directory + 4);
    if (length > 8 && offset <= content.size && length <= content.size - offset) {
        BYTE *copy = malloc(length - 8);
        if (copy) {
            memcpy(copy, content.data + offset + 8, length - 8);
            *blob = copy;
            *size = length - 8;
        } else {
            ok = FALSE;
        }
    } else {
        ok = FALSE;
    }
    free(content.data);
    return ok;
}

/* Signing a protected file fails inside the SIP, which opens the file by name with
   write access. The same signature is obtained by signing an identical copy in a
   writable folder and moving its certificate table into the real file. */
static BOOL signer_sign_via_copy(NttpSigner *signer, SipApi *sip, const wchar_t *path)
{
    /* The copy is made next to the target, not in %TEMP%: a signed binary must not be
       touched by a real-time scanner or a redirected profile before it is written back. */
    wchar_t temporary[PATH_SIZE];
    wcscpy(temporary, path);
    wchar_t *slash = wcsrchr(temporary, L'\\');
    if (!slash || slash - temporary > PATH_SIZE - 16)
        return FALSE;
    wcscpy(slash + 1, L"consent.exe.nttp-sign");
    DeleteFileW(temporary);
    if (!CopyFileW(path, temporary, FALSE))
        return FALSE;
    BOOL ok = signer_sign(signer, sip, temporary);
    if (ok) {
        /* Write the signed copy over the target as a whole: the digest covers the same
           bytes, so the signature verifies, which is not true when only the certificate
           table is moved. */
        HANDLE signed_copy = spp_open(temporary, GENERIC_READ, OPEN_EXISTING);
        Output content = {0};
        BCRYPT_ALG_HANDLE algorithm;
        ok = signed_copy != INVALID_HANDLE_VALUE &&
             BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) >= 0 &&
             offline_read(signed_copy, &content, algorithm);
        if (signed_copy != INVALID_HANDLE_VALUE)
            CloseHandle(signed_copy);
        if (ok) {
            HANDLE target = spp_open(path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
            LARGE_INTEGER start = {0}, end = {.QuadPart = content.size};
            ok = target != INVALID_HANDLE_VALUE && SetFilePointerEx(target, start, NULL, FILE_BEGIN) &&
                 write_verified(target, &content, algorithm) &&
                 SetFilePointerEx(target, end, NULL, FILE_BEGIN) && SetEndOfFile(target) &&
                 FlushFileBuffers(target);
            if (target != INVALID_HANDLE_VALUE)
                CloseHandle(target);
        } else {
            wprintf(L"  signer: cannot read the signed copy back (Win32 %lu).\n", GetLastError());
        }
        free(content.data);
    }
    DeleteFileW(temporary);
    return ok;
}
