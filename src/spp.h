#include <aclapi.h>
#include <sddl.h>
#include <winver.h>

typedef struct {
    wchar_t source[PATH_SIZE], target[PATH_SIZE];
    wchar_t staged[PATH_SIZE], backup[PATH_SIZE];
    wchar_t retired_path[PATH_SIZE], retired_backup[PATH_SIZE];
    BOOL catroot, service, made, saved, installed, retired;
} SppFile;

typedef struct {
    wchar_t path[PATH_SIZE];
    BOOL service, created;
} SppDirectory;

typedef struct {
    SppFile *files;
    SppDirectory *directories;
    size_t count, allocated, dir_count, dir_allocated;
    PSID owner_sid, service_sid;
    WORD machine;
} SppPlan;

static BOOL spp_missing(DWORD error)
{
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

static BOOL spp_path_type(const wchar_t *path, BOOL directory, BOOL optional)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return optional && spp_missing(GetLastError());
    if (!!(attributes & FILE_ATTRIBUTE_DIRECTORY) != directory)
        return FALSE;
    if (!(attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return TRUE;
    if (directory)
        return FALSE;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(path, &data);
    if (find == INVALID_HANDLE_VALUE)
        return FALSE;
    FindClose(find);
    /* DISM projects regular files through the WIM filter, without a link target. */
    return data.dwReserved0 == IO_REPARSE_TAG_WIM;
}

/* Reject reparse ancestors so the donor and target stay under their roots. */
static BOOL spp_path_chain(const wchar_t *path, BOOL include_leaf)
{
    wchar_t part[PATH_SIZE];
    wcscpy(part, path);
    for (wchar_t *p = part + 3; *p; ++p) {
        if (*p != L'\\')
            continue;
        *p = L'\0';
        BOOL ok = spp_path_type(part, TRUE, TRUE);
        *p = L'\\';
        if (!ok)
            return FALSE;
    }
    return !include_leaf || spp_path_type(part, TRUE, FALSE);
}

static WORD spp_pe_machine(const wchar_t *path)
{
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 0;
    BYTE dos[64], pe[26];
    DWORD size;
    LARGE_INTEGER offset = {0};
    BOOL ok = ReadFile(file, dos, sizeof dos, &size, NULL) && size == sizeof dos &&
              !memcmp(dos, "MZ", 2);
    if (ok) {
        offset.QuadPart = u32(dos + 60);
        ok = offset.QuadPart >= 64 && SetFilePointerEx(file, offset, NULL, FILE_BEGIN) &&
             ReadFile(file, pe, sizeof pe, &size, NULL) && size == sizeof pe &&
             u32(pe) == IMAGE_NT_SIGNATURE;
    }
    CloseHandle(file);
    if (!ok)
        return 0;
    WORD machine = u16(pe + 4), magic = u16(pe + 24);
    return (machine == IMAGE_FILE_MACHINE_AMD64 && magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
           (machine == IMAGE_FILE_MACHINE_I386 && magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?
           machine : 0;
}

static BOOL spp_ext(const wchar_t *name, const wchar_t *const extensions[])
{
    const wchar_t *ext = wcsrchr(name, L'.');
    if (!ext)
        return FALSE;
    for (unsigned i = 0; extensions[i]; ++i)
        if (!_wcsicmp(ext, extensions[i]))
            return TRUE;
    return FALSE;
}

static const wchar_t *const spp_certificates[] = {
    L".cat", L".cer", L".crt", L".der", L".p7b", L".p7c", L".sst", NULL
};

static BOOL spp_add_directory(SppPlan *plan, const wchar_t *target, BOOL service)
{
    if (!spp_path_type(target, TRUE, TRUE))
        return FALSE;
    for (size_t i = 0; i < plan->dir_count; ++i)
        if (!_wcsicmp(plan->directories[i].path, target))
            return TRUE;
    if (plan->dir_count == plan->dir_allocated) {
        size_t capacity = plan->dir_allocated ? plan->dir_allocated * 2 : 32;
        SppDirectory *entries = realloc(plan->directories, capacity * sizeof *entries);
        if (!entries)
            return FALSE;
        plan->directories = entries;
        plan->dir_allocated = capacity;
    }
    SppDirectory *entry = &plan->directories[plan->dir_count++];
    *entry = (SppDirectory){.service = service};
    wcscpy(entry->path, target);
    return TRUE;
}

static BOOL spp_add_file(SppPlan *plan, const wchar_t *source, const wchar_t *target,
                         BOOL catroot, BOOL service, BOOL check_machine)
{
    static const wchar_t *const binaries[] = {L".dll", L".exe", L".sys", L".cpl", L".ocx", NULL};
    if (!spp_path_type(source, FALSE, FALSE) || !spp_path_type(target, FALSE, TRUE)) {
        fwprintf(stderr, L"Invalid SPP source or destination: %ls -> %ls.\n", source, target);
        return FALSE;
    }
    for (size_t i = 0; i < plan->count; ++i) {
        if (!_wcsicmp(plan->files[i].target, target)) {
            fwprintf(stderr, L"More than one SPP donor maps to %ls.\n", target);
            return FALSE;
        }
    }
    HANDLE input = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (input == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Cannot read SPP donor %ls (Win32 %lu).\n", source, GetLastError());
        return FALSE;
    }
    CloseHandle(input);
    if (check_machine && spp_ext(source, binaries) && spp_pe_machine(source) != plan->machine) {
        fwprintf(stderr, L"SPP donor architecture mismatch or invalid PE: %ls.\n", source);
        return FALSE;
    }
    if (plan->count == plan->allocated) {
        size_t capacity = plan->allocated ? plan->allocated * 2 : 128;
        SppFile *entries = realloc(plan->files, capacity * sizeof *entries);
        if (!entries)
            return FALSE;
        plan->files = entries;
        plan->allocated = capacity;
    }
    SppFile *entry = &plan->files[plan->count];
    *entry = (SppFile){.catroot = catroot, .service = service};
    wcscpy(entry->source, source);
    wcscpy(entry->target, target);
    if (swprintf(entry->staged, PATH_SIZE, L"%ls.fp-%lu-%zu-new", target, GetCurrentProcessId(), plan->count) < 0 ||
        swprintf(entry->backup, PATH_SIZE, L"%ls.fp-%lu-%zu-old", target, GetCurrentProcessId(), plan->count) < 0)
        return FALSE;
    if (GetFileAttributesW(entry->staged) != INVALID_FILE_ATTRIBUTES || !spp_missing(GetLastError()) ||
        GetFileAttributesW(entry->backup) != INVALID_FILE_ATTRIBUTES || !spp_missing(GetLastError()))
        return FALSE;
    ++plan->count;
    return TRUE;
}

static BOOL spp_collect(SppPlan *plan, const wchar_t *source, const wchar_t *target,
                        const wchar_t *relative, BOOL catroot)
{
    BOOL top = !*relative;
    BOOL service = !catroot && (!_wcsicmp(relative, L"spp\\store\\2.0") ||
                                !_wcsnicmp(relative, L"spp\\store\\2.0\\", 14));
    wchar_t pattern[PATH_SIZE];
    if (!build_path(pattern, source, top ? L"spp*" : L"*"))
        return FALSE;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    BOOL ok = TRUE;
    do {
        const wchar_t *name = data.cFileName;
        BOOL directory = !!(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
        if (!wcscmp(name, L".") || !wcscmp(name, L"..") || !_wcsicmp(name, L"sppnp.dll"))
            continue;
        if ((top && (directory || _wcsnicmp(name, L"spp", 3))) ||
            (catroot && !directory && !spp_ext(name, spp_certificates)))
            continue;
        wchar_t src[PATH_SIZE], dst[PATH_SIZE], child[PATH_SIZE];
        if (((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
             (directory || data.dwReserved0 != IO_REPARSE_TAG_WIM)) ||
            !build_path(src, source, name) || !build_path(dst, target, name)) {
            ok = FALSE;
            break;
        }
        if (directory) {
            size_t old_files = plan->count, old_directories = plan->dir_count;
            if (!build_path(child, relative, name) ||
                !spp_add_directory(plan, dst, service ||
                                   !_wcsicmp(child, L"spp\\store\\2.0")) ||
                !spp_collect(plan, src, dst, child, catroot)) {
                ok = FALSE;
                break;
            }
            if (catroot && plan->count == old_files)
                plan->dir_count = old_directories;
        } else if (!spp_add_file(plan, src, dst, catroot,
                                service || (top && !_wcsicmp(name, L"sppsvc.exe")), top)) {
            ok = FALSE;
            break;
        }
    } while (FindNextFileW(find, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = FALSE;
    FindClose(find);
    return ok;
}

static BOOL spp_collect_flat_catalogs(SppPlan *plan, const wchar_t *source, const wchar_t *catroot)
{
    static const wchar_t catalog_group[] = L"{F750E6C3-38EE-11D1-85E5-00C04FC295EE}";
    wchar_t pattern[PATH_SIZE], group[PATH_SIZE];
    if (!build_path(pattern, source, L"*") || !build_path(group, catroot, catalog_group))
        return FALSE;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(pattern, &data);
    if (find == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND;
    BOOL ok = TRUE;
    do {
        const wchar_t *name = data.cFileName;
        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || !spp_ext(name, spp_certificates))
            continue;
        wchar_t src[PATH_SIZE], dst[PATH_SIZE];
        ok = build_path(src, source, name) && build_path(dst, group, name) &&
             spp_add_directory(plan, catroot, FALSE) && spp_add_directory(plan, group, FALSE) &&
             spp_add_file(plan, src, dst, TRUE, FALSE, FALSE);
    } while (ok && FindNextFileW(find, &data));
    if (ok && GetLastError() != ERROR_NO_MORE_FILES)
        ok = FALSE;
    FindClose(find);
    return ok;
}

static BOOL spp_kernel_version(const wchar_t *kernel, wchar_t version[24])
{
    DWORD unused = 0;
    DWORD size = GetFileVersionInfoSizeW(kernel, &unused);
    void *data = size ? malloc(size) : NULL;
    VS_FIXEDFILEINFO *info;
    UINT length;
    BOOL ok = data && GetFileVersionInfoW(kernel, 0, size, data) &&
              VerQueryValueW(data, L"\\", (void **)&info, &length) &&
              length >= sizeof *info && info->dwSignature == 0xfeef04bdu &&
              swprintf(version, 24, L"%u.%u.%u.%u", HIWORD(info->dwFileVersionMS),
                       LOWORD(info->dwFileVersionMS), HIWORD(info->dwFileVersionLS),
                       LOWORD(info->dwFileVersionLS)) > 0;
    free(data);
    return ok;
}

static BOOL spp_catalog_version(const wchar_t *version)
{
    for (unsigned part = 0; part < 4; ++part) {
        if (*version < L'0' || *version > L'9')
            return FALSE;
        do {
            ++version;
        } while (*version >= L'0' && *version <= L'9');
        if (part < 3 && *version++ != L'.')
            return FALSE;
    }
    return !_wcsicmp(version, L".cat");
}

/* Retire only the target build's catalog for a supplied SPP SKU identity. */
static BOOL spp_plan_old_catalogs(SppPlan *plan, const wchar_t *kernel)
{
    static const wchar_t sku[] = L"Microsoft-Windows-Security-SPP-Component-SKU-";
    wchar_t version[24] = {0};
    for (size_t i = 0; i < plan->count; ++i) {
        SppFile *entry = &plan->files[i];
        if (!entry->catroot)
            continue;
        const wchar_t *name = wcsrchr(entry->target, L'\\') + 1;
        const wchar_t *suffix = wcsrchr(name, L'~');
        if (_wcsnicmp(name, sku, sizeof sku / sizeof sku[0] - 1) || !suffix ||
            !spp_catalog_version(suffix + 1))
            continue;
        if (!version[0] && !spp_kernel_version(kernel, version)) {
            fwprintf(stderr, L"Cannot determine the target version for SPP catalog cleanup: %ls.\n", kernel);
            return FALSE;
        }
        wchar_t original[PATH_SIZE];
        if (swprintf(original, PATH_SIZE, L"%.*ls%ls.cat", (int)(suffix + 1 - entry->target),
                     entry->target, version) < 0)
            return FALSE;
        BOOL keep = FALSE;
        for (size_t j = 0; j < plan->count && !keep; ++j)
            keep = !_wcsicmp(original, plan->files[j].target) ||
                   !_wcsicmp(original, plan->files[j].retired_path);
        if (keep)
            continue;
        if (GetFileAttributesW(original) == INVALID_FILE_ATTRIBUTES && spp_missing(GetLastError()))
            continue;
        if (!spp_path_type(original, FALSE, FALSE) ||
            swprintf(entry->retired_backup, PATH_SIZE, L"%ls.fp-%lu-%zu-oldcat", original,
                     GetCurrentProcessId(), i) < 0) {
            fwprintf(stderr, L"Cannot prepare old SPP catalog %ls.\n", original);
            return FALSE;
        }
        wcscpy(entry->retired_path, original);
    }
    return TRUE;
}

/* Reuse the destination ACL and grant the service access on the specified paths. */
static DWORD spp_acl(HANDLE file, HANDLE old, const SppPlan *plan, BOOL catroot,
                     BOOL service, BOOL directory)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PACL dacl = NULL, new_dacl = NULL;
    PSID owner = NULL, group = NULL;
    SECURITY_INFORMATION flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    HANDLE base = old != INVALID_HANDLE_VALUE ? old : file;
    DWORD error = GetSecurityInfo(base, SE_FILE_OBJECT, flags, &owner, &group, &dacl, NULL, &descriptor);
    if (error == ERROR_SUCCESS && service) {
        EXPLICIT_ACCESSW entry = {
            .grfAccessPermissions = FILE_ALL_ACCESS,
            .grfAccessMode = SET_ACCESS,
            .grfInheritance = directory ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE
        };
        BuildTrusteeWithSidW(&entry.Trustee, plan->service_sid);
        error = SetEntriesInAclW(1, &entry, dacl, &new_dacl);
        if (error == ERROR_SUCCESS)
            dacl = new_dacl;
    }
    if (error == ERROR_SUCCESS) {
        SECURITY_DESCRIPTOR_CONTROL control;
        DWORD revision;
        if (!GetSecurityDescriptorControl(descriptor, &control, &revision))
            error = GetLastError();
        else {
            if (!catroot && !directory)
                owner = plan->owner_sid;
            if (old == INVALID_HANDLE_VALUE)
                flags = catroot || directory ? 0 : OWNER_SECURITY_INFORMATION;
            if (service || old != INVALID_HANDLE_VALUE || (!catroot && !directory)) {
                flags |= DACL_SECURITY_INFORMATION;
                if (control & SE_DACL_PROTECTED)
                    flags |= PROTECTED_DACL_SECURITY_INFORMATION;
            }
            if (flags)
                error = SetSecurityInfo(file, SE_FILE_OBJECT, flags, owner, group, dacl, NULL);
        }
    }
    LocalFree(new_dacl);
    LocalFree(descriptor);
    return error;
}

static HANDLE spp_open(const wchar_t *path, DWORD access, DWORD disposition)
{
    DWORD attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_REPARSE_POINT) &&
        !spp_path_type(path, FALSE, FALSE)) {
        SetLastError(ERROR_INVALID_REPARSE_DATA);
        return INVALID_HANDLE_VALUE;
    }
    return CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, disposition, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

static BOOL spp_rename(HANDLE file, const wchar_t *destination)
{
    union {
        FILE_RENAME_INFO info;
        BYTE bytes[sizeof(FILE_RENAME_INFO) + PATH_SIZE * sizeof(wchar_t)];
    } rename = {0};
    rename.info.FileNameLength = (DWORD)(wcslen(destination) * sizeof(wchar_t));
    wcscpy(rename.info.FileName, destination);
    return SetFileInformationByHandle(file, FileRenameInfo, &rename,
                                      sizeof(FILE_RENAME_INFO) + rename.info.FileNameLength);
}

static BOOL spp_remove(const wchar_t *path)
{
    HANDLE file = spp_open(path, DELETE, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE)
        return spp_missing(GetLastError());
    FILE_DISPOSITION_INFO disposition = {.DeleteFile = TRUE};
    BOOL ok = SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof disposition);
    CloseHandle(file);
    return ok;
}

static BOOL spp_copy_verified(HANDLE source, HANDLE destination)
{
    BYTE *buffer = malloc(128 * 1024);
    if (!buffer)
        return FALSE;
    DWORD length = 0, written, read;
    LARGE_INTEGER start = {0};
    BOOL ok = TRUE;
    do {
        ok = ReadFile(source, buffer, 64 * 1024, &length, NULL) &&
             WriteFile(destination, buffer, length, &written, NULL) && written == length;
    } while (ok && length);
    ok = ok && FlushFileBuffers(destination) &&
         SetFilePointerEx(source, start, NULL, FILE_BEGIN) &&
         SetFilePointerEx(destination, start, NULL, FILE_BEGIN);
    do {
        if (!ok)
            break;
        ok = ReadFile(source, buffer, 64 * 1024, &length, NULL) &&
             ReadFile(destination, buffer + 64 * 1024, 64 * 1024, &read, NULL) &&
             length == read && !memcmp(buffer, buffer + 64 * 1024, length);
    } while (ok && length);
    free(buffer);
    return ok;
}

static BOOL spp_stage(SppPlan *plan, SppFile *entry)
{
    HANDLE source = spp_open(entry->source, GENERIC_READ, OPEN_EXISTING);
    HANDLE old = spp_open(entry->target, READ_CONTROL, OPEN_EXISTING);
    DWORD error = old == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    HANDLE output = INVALID_HANDLE_VALUE;
    BOOL ok = source != INVALID_HANDLE_VALUE && (old != INVALID_HANDLE_VALUE || spp_missing(error));
    if (ok) {
        output = spp_open(entry->staged, GENERIC_READ | GENERIC_WRITE | WRITE_OWNER | WRITE_DAC, CREATE_NEW);
        entry->made = output != INVALID_HANDLE_VALUE;
        ok = entry->made && spp_copy_verified(source, output);
    }
    if (ok) {
        error = spp_acl(output, old, plan, entry->catroot, entry->service, FALSE);
        ok = error == ERROR_SUCCESS;
    } else {
        error = GetLastError();
    }
    if (output != INVALID_HANDLE_VALUE)
        CloseHandle(output);
    if (old != INVALID_HANDLE_VALUE)
        CloseHandle(old);
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (!ok)
        fwprintf(stderr, L"Cannot stage SPP file %ls (Win32 %lu).\n", entry->target, error);
    return ok;
}

static BOOL spp_publish(SppFile *entry)
{
    if (!spp_path_chain(entry->target, FALSE) || !spp_path_type(entry->target, FALSE, TRUE))
        return FALSE;
    HANDLE original = spp_open(entry->target, DELETE, OPEN_EXISTING);
    if (original == INVALID_HANDLE_VALUE) {
        if (!spp_missing(GetLastError()))
            return FALSE;
    } else {
        entry->saved = spp_rename(original, entry->backup);
        CloseHandle(original);
        if (!entry->saved)
            return FALSE;
    }
    HANDLE staged = spp_open(entry->staged, DELETE, OPEN_EXISTING);
    if (staged == INVALID_HANDLE_VALUE)
        return FALSE;
    entry->installed = spp_rename(staged, entry->target);
    CloseHandle(staged);
    return entry->installed;
}

static BOOL spp_retire(SppFile *entry)
{
    if (!entry->retired_path[0])
        return TRUE;
    if (!spp_path_chain(entry->retired_path, FALSE) || !spp_path_type(entry->retired_path, FALSE, TRUE))
        return FALSE;
    HANDLE old = spp_open(entry->retired_path, DELETE, OPEN_EXISTING);
    if (old == INVALID_HANDLE_VALUE)
        return spp_missing(GetLastError());
    entry->retired = spp_rename(old, entry->retired_backup);
    CloseHandle(old);
    return entry->retired;
}

static void spp_restore(const wchar_t *backup_path, const wchar_t *target)
{
    HANDLE backup = spp_open(backup_path, DELETE, OPEN_EXISTING);
    if (backup == INVALID_HANDLE_VALUE || !spp_rename(backup, target))
        fwprintf(stderr, L"Original retained at %ls.\n", backup_path);
    if (backup != INVALID_HANDLE_VALUE)
        CloseHandle(backup);
}

static BOOL spp_apply(SppPlan *plan)
{
    BOOL ok = TRUE;
    for (size_t i = 0; i < plan->dir_count && ok; ++i) {
        SppDirectory *entry = &plan->directories[i];
        if (spp_path_type(entry->path, TRUE, FALSE))
            continue;
        entry->created = CreateDirectoryW(entry->path, NULL);
        ok = entry->created;
        if (ok && entry->service) {
            HANDLE directory = spp_open(entry->path, READ_CONTROL | WRITE_OWNER | WRITE_DAC, OPEN_EXISTING);
            ok = directory != INVALID_HANDLE_VALUE;
            if (ok) {
                ok = spp_acl(directory, INVALID_HANDLE_VALUE, plan, FALSE, entry->service, TRUE) == ERROR_SUCCESS;
                CloseHandle(directory);
            }
        }
        if (!ok)
            fwprintf(stderr, L"Cannot create SPP directory %ls.\n", entry->path);
    }
    size_t staged = 0;
    while (ok && staged < plan->count)
        ok = spp_stage(plan, &plan->files[staged++]);
    for (size_t i = 0; i < plan->count && ok; ++i) {
        ok = spp_publish(&plan->files[i]);
        if (!ok)
            fwprintf(stderr, L"Cannot publish SPP file %ls (Win32 %lu).\n",
                     plan->files[i].target, GetLastError());
    }
    for (size_t i = 0; i < plan->count && ok; ++i) {
        ok = spp_retire(&plan->files[i]);
        if (!ok)
            fwprintf(stderr, L"Cannot retire old SPP catalog %ls (Win32 %lu).\n",
                     plan->files[i].retired_path, GetLastError());
    }
    for (size_t i = staged; i > 0; --i) {
        SppFile *entry = &plan->files[i - 1];
        if (entry->retired) {
            if (!ok)
                spp_restore(entry->retired_backup, entry->retired_path);
            else if (spp_remove(entry->retired_backup))
                wprintf(L"Removed old SPP catalog %ls.\n", entry->retired_path);
            else
                fwprintf(stderr, L"Old SPP catalog backup retained at %ls.\n", entry->retired_backup);
        }
        if (!ok && entry->installed && !spp_remove(entry->target))
            fwprintf(stderr, L"Cannot remove replacement during rollback: %ls.\n", entry->target);
        if (!ok && entry->saved)
            spp_restore(entry->backup, entry->target);
        else if (ok && entry->saved && !spp_remove(entry->backup))
            fwprintf(stderr, L"Original retained at %ls.\n", entry->backup);
        if (entry->made && !entry->installed && !spp_remove(entry->staged))
            fwprintf(stderr, L"Cannot remove staged file %ls.\n", entry->staged);
    }
    if (!ok) {
        for (size_t i = plan->dir_count; i > 0; --i)
            if (plan->directories[i - 1].created)
                RemoveDirectoryW(plan->directories[i - 1].path);
    }
    return ok;
}

static BOOL replace_spp(const wchar_t *source, const wchar_t *target, BOOL check_only)
{
    static const wchar_t *const layouts[] = {L"Windows\\System32", L"System32", L""};
    wchar_t donor[PATH_SIZE], system32[PATH_SIZE], probe[PATH_SIZE];
    BOOL located = FALSE;
    for (unsigned i = 0; i < sizeof layouts / sizeof layouts[0]; ++i) {
        if (*layouts[i]) {
            if (!build_path(donor, source, layouts[i]))
                continue;
        } else {
            wcscpy(donor, source);
        }
        if (spp_path_chain(donor, TRUE) && build_path(probe, donor, L"sppsvc.exe") &&
            spp_path_type(probe, FALSE, FALSE)) {
            located = TRUE;
            break;
        }
    }
    if (!located || !build_path(system32, target, L"Windows\\System32") ||
        !spp_path_chain(system32, TRUE) || !_wcsicmp(donor, system32)) {
        fwprintf(stderr, L"Provide separate SPP donor and offline Windows target directories.\n");
        return FALSE;
    }
    SppPlan plan = {0};
    if (!build_path(probe, system32, L"ntoskrnl.exe") || !spp_path_type(probe, FALSE, FALSE) ||
        !(plan.machine = spp_pe_machine(probe))) {
        fwprintf(stderr, L"Cannot determine the target Windows architecture.\n");
        return FALSE;
    }
    BOOL ok = spp_collect(&plan, donor, system32, L"", FALSE) && plan.count;
    if (!ok)
        fwprintf(stderr, L"Cannot prepare spp* files in %ls.\n", donor);
    wchar_t src[PATH_SIZE], dst[PATH_SIZE];
    if (ok) {
        size_t before = plan.count;
        ok = build_path(src, donor, L"spp") && build_path(dst, system32, L"spp") &&
             spp_path_type(src, TRUE, FALSE) && spp_add_directory(&plan, dst, FALSE) &&
             spp_collect(&plan, src, dst, L"spp", FALSE) && plan.count > before;
        if (!ok)
            fwprintf(stderr, L"Cannot prepare the spp tree in %ls.\n", donor);
    }
    if (ok) {
        size_t before = plan.count;
        ok = build_path(src, donor, L"CatRoot") && build_path(dst, system32, L"CatRoot");
        if (ok && spp_path_type(src, TRUE, FALSE))
            ok = spp_add_directory(&plan, dst, FALSE) && spp_collect(&plan, src, dst, L"CatRoot", TRUE);
        else if (ok)
            ok = spp_path_type(src, TRUE, TRUE);
        if (ok)
            ok = spp_collect_flat_catalogs(&plan, donor, dst) && plan.count > before;
        if (!ok)
            fwprintf(stderr, L"Cannot prepare CatRoot files from %ls. Supply a catalog beside sppsvc.exe or files under CatRoot.\n", donor);
    }
    if (ok)
        ok = spp_plan_old_catalogs(&plan, probe);
    if (ok && !check_only) {
        ok = ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
                                    &plan.owner_sid) &&
             ConvertStringSidToSidW(L"S-1-5-80-123231216-2592883651-3715271367-3753151631-4175906628",
                                    &plan.service_sid) && spp_apply(&plan);
    }
    if (ok)
        wprintf(check_only ? L"SPP preflight passed for %zu files.\n" : L"Replaced %zu SPP files.\n", plan.count);
    LocalFree(plan.owner_sid);
    LocalFree(plan.service_sid);
    free(plan.files);
    free(plan.directories);
    return ok;
}
