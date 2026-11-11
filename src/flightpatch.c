#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <aclapi.h>
#include <bcrypt.h>
#include <sddl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wincrypt.h>
#include <mscat.h>
#include <ncrypt.h>
#include <softpub.h>
#include "version.h"

enum { PATH_SIZE = MAX_PATH, MAX_IMAGE = 32 * 1024 * 1024 };

static BOOL in_winpe(void)
{
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",
                      0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        return FALSE;
    RegCloseKey(key);
    return TRUE;
}

static BOOL is_system(void)
{
    HANDLE token;
    DWORD length;
    BOOL system = FALSE;
    union {
        TOKEN_USER user;
        BYTE bytes[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    } buffer;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return FALSE;
    if (GetTokenInformation(token, TokenUser, &buffer, sizeof buffer, &length))
        system = IsWellKnownSid(buffer.user.User.Sid, WinLocalSystemSid);
    CloseHandle(token);
    return system;
}

static BOOL enable_privilege(const wchar_t *name)
{
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;
    TOKEN_PRIVILEGES privilege = {.PrivilegeCount = 1};
    privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = LookupPrivilegeValueW(NULL, name, &privilege.Privileges[0].Luid) &&
              AdjustTokenPrivileges(token, FALSE, &privilege, 0, NULL, NULL) &&
              GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static void privilege_hint(void)
{
    fwprintf(stderr, L"For protected files, start this tool from a TrustedInstaller or SYSTEM command prompt.\n"
                     L"With NSudo: NSudoLC.exe -U:T -P:E cmd.exe\n"
                     L"        or: NSudoLC.exe -U:S -P:E cmd.exe\n"
                     L"In WinPE, use the SYSTEM command prompt.\n");
}

static BOOL build_path(wchar_t path[PATH_SIZE], const wchar_t *folder,
                       const wchar_t *name)
{
    size_t length = wcslen(folder);
    const wchar_t *separator = length && folder[length - 1] == L'\\' ? L"" : L"\\";
    return swprintf(path, PATH_SIZE, L"%ls%ls%ls", folder, separator, name) >= 0;
}

static BOOL normalize(wchar_t path[PATH_SIZE], const wchar_t *argument)
{
    wchar_t drive[4] = {0};
    if (wcslen(argument) == 2 && argument[1] == L':') {
        drive[0] = argument[0];
        drive[1] = L':';
        drive[2] = L'\\';
        argument = drive;
    }
    DWORD length = GetFullPathNameW(argument, PATH_SIZE, path, NULL);
    if (length < 3 || length >= PATH_SIZE || path[1] != L':' || path[2] != L'\\')
        return FALSE;
    while (length > 3 && path[length - 1] == L'\\')
        path[--length] = L'\0';
    return TRUE;
}

static BOOL digest(BCRYPT_ALG_HANDLE algorithm, BYTE *data, DWORD size, char hex[65])
{
    static const char digits[] = "0123456789abcdef";
    BCRYPT_HASH_HANDLE hash;
    BYTE result[32];

    if (BCryptCreateHash(algorithm, &hash, NULL, 0, NULL, 0, 0) < 0)
        return FALSE;
    BOOL ok = BCryptHashData(hash, data, size, 0) >= 0 &&
              BCryptFinishHash(hash, result, sizeof result, 0) >= 0;
    BCryptDestroyHash(hash);
    if (!ok)
        return FALSE;
    for (size_t i = 0; i < sizeof result; ++i) {
        hex[i * 2] = digits[result[i] >> 4];
        hex[i * 2 + 1] = digits[result[i] & 15];
    }
    hex[64] = '\0';
    return TRUE;
}

static BOOL fix_checksum(BYTE *data, DWORD size)
{
    uint32_t pe_offset, signature;
    uint16_t machine, magic;
    if (size < 0x5c || memcmp(data, "MZ", 2))
        return FALSE;
    memcpy(&pe_offset, data + 0x3c, sizeof pe_offset);
    if (pe_offset > size - 0x5c)
        return FALSE;
    memcpy(&signature, data + pe_offset, sizeof signature);
    memcpy(&machine, data + pe_offset + 4, sizeof machine);
    memcpy(&magic, data + pe_offset + 24, sizeof magic);
    BOOL pe32 = machine == IMAGE_FILE_MACHINE_I386 && magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    BOOL pe64 = (machine == IMAGE_FILE_MACHINE_AMD64 || machine == IMAGE_FILE_MACHINE_ARM64) &&
                magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    if (signature != IMAGE_NT_SIGNATURE || (!pe32 && !pe64))
        return FALSE;

    DWORD offset = pe_offset + 0x58;
    memset(data + offset, 0, 4);
    uint32_t sum = 0;
    for (DWORD i = 0; i < size; i += 2) {
        sum += data[i];
        if (i + 1 < size)
            sum += (uint32_t)data[i + 1] << 8;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ((sum & 0xffff) + (sum >> 16)) + size;
    memcpy(data + offset, &sum, sizeof sum);
    return TRUE;
}

__declspec(dllimport) LONG NTAPI RtlGetCompressionWorkSpaceSize(USHORT, ULONG *, ULONG *);
__declspec(dllimport) LONG NTAPI RtlDecompressBufferEx(USHORT, BYTE *, ULONG, BYTE *, ULONG, ULONG *, void *);
__declspec(dllimport) LONG NTAPI RtlCompressBuffer(USHORT, BYTE *, ULONG, BYTE *, ULONG, ULONG, ULONG *, void *);

#include "matchers.h"

typedef enum { CI, KERNEL, LOADER, BOOT, LEGACY, HVLOADER } Role;
typedef struct {
    const wchar_t *name;
    const wchar_t *image_path;
    Role role;
    BOOL required;
} File;

static const File files[] = {
    {L"ci.dll", L"Windows\\System32\\ci.dll", CI, TRUE},
    {L"ntoskrnl.exe", L"Windows\\System32\\ntoskrnl.exe", KERNEL, FALSE},
    {L"bootmgfw.efi", L"Windows\\Boot\\EFI\\bootmgfw.efi", BOOT, FALSE},
    {L"bootmgr.efi", L"Windows\\Boot\\EFI\\bootmgr.efi", BOOT, FALSE},
    {L"memtest.efi", L"Windows\\Boot\\EFI\\memtest.efi", BOOT, FALSE},
    {L"winload.efi", L"Windows\\System32\\winload.efi", LOADER, FALSE},
    {L"winresume.efi", L"Windows\\System32\\winresume.efi", LOADER, FALSE},
    {L"bootmgr", L"Windows\\Boot\\PCAT\\bootmgr", LEGACY, FALSE},
    {L"memtest.exe", L"Windows\\Boot\\PCAT\\memtest.exe", BOOT, FALSE},
    {L"winload.exe", L"Windows\\System32\\winload.exe", LOADER, FALSE},
    {L"winresume.exe", L"Windows\\System32\\winresume.exe", LOADER, FALSE},
    {L"hvloader.efi", L"Windows\\System32\\hvloader.efi", HVLOADER, FALSE},
    {L"hvloader.exe", L"Windows\\System32\\hvloader.exe", HVLOADER, FALSE}
};

enum { HV_FIRST = 11, FILE_COUNT = sizeof files / sizeof files[0] };

typedef struct {
    BYTE *data;
    DWORD size;
    WORD machine;
    char sha[65];
    BOOL changed;
} Output;

static BOOL patch_pe(BYTE *data, DWORD size, Role role, WORD *machine, BOOL *changed)
{
    Image im;
    if (!image_open(&im, data, size))
        return FALSE;
    Plan plan = {0};
    BOOL valid = role == CI ? plan_ci(&im, &plan) :
                 role == KERNEL ? plan_kernel(&im, &plan) :
                 role == HVLOADER ? plan_hvloader(&im, &plan) && plan_boot(&im, &plan, TRUE) :
                 plan_boot(&im, &plan, role == LOADER);
    if (!valid || (!plan.count && !plan.existing))
        return FALSE;

    for (unsigned i = 0; i < plan.count; ++i) {
        const Change *e = &plan.edits[i];
        memcpy(data + e->at, e->bytes, e->length);
        wprintf(L"  %06lX  %ls\n", e->at, e->label);
    }
    *changed = plan.count != 0;
    *machine = im.x64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
    return !*changed || fix_checksum(data, size);
}

static BOOL patch_legacy(Output *out)
{
    enum { XPRESS_HUFF = 4, MAXIMUM = 0x100 };
    DWORD header = NONE, payload = 0, packed = 0, unpacked = 0, padding = 0;
    BYTE *data = out->data;
    for (DWORD i = 0; i + 32 < out->size && i < 0x40000; ++i) {
        if (data[i] != 'B' || memcmp(data + i, "BMXH", 4) || memcmp(data + i + 16, "MZ", 2))
            continue;
        DWORD offset = u32(data + i + 12), len = u32(data + i + 4);
        DWORD original = u32(data + i + 8);
        if (offset < 0x110 || offset > out->size - i || !len || len > out->size - i - offset ||
            original < 0x100 || original > MAX_IMAGE || out->size - i - offset - len > 16)
            continue;
        if (header != NONE)
            return FALSE;
        header = i;
        payload = i + offset;
        packed = len;
        unpacked = original;
        padding = out->size - payload - packed;
    }
    if (header == NONE)
        return FALSE;
    for (DWORD i = 0; i < padding; ++i)
        if (data[payload + packed + i] != 0)
            return FALSE;

    ULONG compress_size, decompress_size, actual;
    if (RtlGetCompressionWorkSpaceSize(XPRESS_HUFF | MAXIMUM, &compress_size, &decompress_size) < 0)
        return FALSE;
    void *workspace = malloc(max(compress_size, decompress_size));
    BYTE *inner = malloc(unpacked);
    BYTE *verify = NULL, *rebuilt = NULL;
    BOOL changed;
    BOOL ok = workspace && inner &&
              RtlDecompressBufferEx(XPRESS_HUFF, inner, unpacked, data + payload, packed,
                                    &actual, workspace) >= 0 && actual == unpacked &&
              patch_pe(inner, unpacked, BOOT, &out->machine, &changed);
    if (ok && changed) {
        DWORD capacity = unpacked + 65536;
        rebuilt = malloc(payload + capacity + padding);
        verify = malloc(unpacked);
        ULONG decoded = 0;
        ok = rebuilt && verify &&
             RtlCompressBuffer(XPRESS_HUFF | MAXIMUM, inner, unpacked, rebuilt + payload,
                               capacity, 4096, &actual, workspace) >= 0 &&
             RtlDecompressBufferEx(XPRESS_HUFF, verify, unpacked, rebuilt + payload, actual,
                                   &decoded, workspace) >= 0 && decoded == unpacked &&
             !memcmp(inner, verify, unpacked);
        if (ok) {
            memcpy(rebuilt, data, payload);
            memcpy(rebuilt + header + 4, &actual, 4);
            memset(rebuilt + payload + actual, 0, padding);
            DWORD size = payload + actual + padding;
            DWORD stub = header + 16;
            ok = fix_checksum(rebuilt + stub, size - stub);
            if (ok) {
                out->data = rebuilt;
                out->size = size;
                rebuilt = NULL;
                free(data);
            }
        }
    }
    free(rebuilt);
    free(verify);
    free(inner);
    free(workspace);
    return ok;
}

static BOOL prepare(BCRYPT_ALG_HANDLE algorithm, const wchar_t *folder, const File *entry,
                    BOOL image, Output *out)
{
    wchar_t path[PATH_SIZE];
    if (!build_path(path, folder, image ? entry->image_path : entry->name)) {
        fwprintf(stderr, L"Input path too long.\n");
        return FALSE;
    }
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (!entry->required && (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND))
            return TRUE;
        fwprintf(stderr, L"Cannot read %ls (Win32 %lu).\n", path, error);
        return FALSE;
    }
    LARGE_INTEGER size;
    DWORD read;
    BOOL ok = GetFileSizeEx(file, &size) && size.QuadPart > 0 && size.QuadPart <= MAX_IMAGE &&
              (out->data = malloc((size_t)size.QuadPart)) &&
              ReadFile(file, out->data, (DWORD)size.QuadPart, &read, NULL) &&
              read == size.QuadPart;
    CloseHandle(file);
    if (!ok) {
        fwprintf(stderr, L"Cannot read all bytes of %ls.\n", path);
        return FALSE;
    }
    out->size = read;
    char before[65];
    if (!digest(algorithm, out->data, out->size, before))
        return FALSE;
    wprintf(L"%ls\n", entry->name);
    BOOL changed;
    ok = entry->role == LEGACY ? patch_legacy(out) :
         patch_pe(out->data, out->size, entry->role, &out->machine, &changed);
    if (!ok || !digest(algorithm, out->data, out->size, out->sha)) {
        fwprintf(stderr, L"  Unsupported or ambiguous structure in %ls.\n", entry->name);
        return FALSE;
    }
    out->changed = strcmp(before, out->sha) != 0;
    wprintf(L"  %ls  SHA-256 %hs\n", out->changed ? L"ready" : L"already patched",
            out->sha);
    return TRUE;
}

static BOOL write_verified(HANDLE file, const Output *image, BCRYPT_ALG_HANDLE algorithm)
{
    DWORD count, size = image->size;
    BYTE *verify = malloc(size);
    char sha[65];
    BOOL ok = verify && WriteFile(file, image->data, size, &count, NULL) &&
              count == size && FlushFileBuffers(file) &&
              SetFilePointer(file, 0, NULL, FILE_BEGIN) == 0 &&
              ReadFile(file, verify, size, &count, NULL) && count == size &&
              digest(algorithm, verify, size, sha) && !strcmp(sha, image->sha);
    free(verify);
    return ok;
}

static BOOL write_output(const wchar_t *output, const Output images[FILE_COUNT],
                         BCRYPT_ALG_HANDLE algorithm)
{
    wchar_t staging[PATH_SIZE], path[PATH_SIZE];
    if (GetFileAttributesW(output) != INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"Output already exists. Use a new directory.\n");
        return FALSE;
    }
    if (swprintf(staging, PATH_SIZE, L"%ls.tmp", output) < 0 ||
        !build_path(path, staging, L"bootmgfw.efi")) {
        fwprintf(stderr, L"Output path too long.\n");
        return FALSE;
    }
    if (!CreateDirectoryW(staging, NULL)) {
        fwprintf(stderr, L"Cannot create staging directory %ls (Win32 %lu).\n",
                 staging, GetLastError());
        return FALSE;
    }
    BOOL ok = TRUE;
    BOOL created[FILE_COUNT] = {0};
    for (unsigned i = 0; i < FILE_COUNT && ok; ++i) {
        if (!images[i].data)
            continue;
        build_path(path, staging, files[i].name);
        HANDLE file = CreateFileW(path, GENERIC_WRITE | GENERIC_READ, 0, NULL,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (file == INVALID_HANDLE_VALUE) {
            fwprintf(stderr, L"Cannot create %ls (Win32 %lu).\n", path, GetLastError());
            ok = FALSE;
            break;
        }
        created[i] = TRUE;
        ok = write_verified(file, &images[i], algorithm);
        CloseHandle(file);
        if (!ok)
            fwprintf(stderr, L"Could not verify written file %ls.\n", path);
    }
    if (ok && MoveFileExW(staging, output, MOVEFILE_WRITE_THROUGH))
        return TRUE;
    if (ok)
        fwprintf(stderr, L"Cannot publish output %ls (Win32 %lu).\n", output, GetLastError());

    for (unsigned i = 0; i < FILE_COUNT; ++i) {
        if (created[i]) {
            build_path(path, staging, files[i].name);
            DeleteFileW(path);
        }
    }
    if (!RemoveDirectoryW(staging))
        fwprintf(stderr, L"Check the staging directory %ls.\n", staging);
    return FALSE;
}

#include "winre.h"
#include "image.h"
#include "spp.h"
#include "nt6.h"
#include "patch_files.h"
#include "restore.h"

static BOOL same_directory(const wchar_t *first, const wchar_t *second, BOOL *same)
{
    HANDLE a = CreateFileW(first, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    HANDLE b = CreateFileW(second, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    BY_HANDLE_FILE_INFORMATION ia, ib;
    BOOL ok = a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE &&
              GetFileInformationByHandle(a, &ia) && GetFileInformationByHandle(b, &ib) &&
              (ia.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
              (ib.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    if (ok)
        *same = ia.dwVolumeSerialNumber == ib.dwVolumeSerialNumber &&
                ia.nFileIndexHigh == ib.nFileIndexHigh && ia.nFileIndexLow == ib.nFileIndexLow;
    if (a != INVALID_HANDLE_VALUE)
        CloseHandle(a);
    if (b != INVALID_HANDLE_VALUE)
        CloseHandle(b);
    return ok;
}

static BOOL offline_root(const wchar_t *root, BOOL require_hive)
{
    wchar_t windows[PATH_SIZE], live[PATH_SIZE], hive[PATH_SIZE];
    UINT length = GetSystemWindowsDirectoryW(live, PATH_SIZE);
    BOOL same;
    if (!length || length >= PATH_SIZE || !build_path(windows, root, L"Windows") ||
        !same_directory(windows, live, &same) || same ||
        !build_path(hive, windows, L"System32\\Config\\SYSTEM"))
        return FALSE;
    return !require_hive || spp_path_type(hive, FALSE, FALSE);
}

static unsigned image_build(const wchar_t *root, BOOL boot_wim)
{
    static const wchar_t *const probes[] = {
        L"ntoskrnl.exe", L"winload.efi", L"winload.exe", L"Boot\\winload.efi", L"Boot\\winload.exe"
    };
    wchar_t system32[PATH_SIZE], path[PATH_SIZE], version[24];
    if (!build_path(system32, root, L"Windows\\System32") || !spp_path_chain(system32, TRUE))
        return 0;
    unsigned count = boot_wim ? sizeof probes / sizeof probes[0] : 1;
    for (unsigned i = 0; i < count; ++i) {
        if (!build_path(path, system32, probes[i]) || !spp_path_chain(path, FALSE) ||
            !spp_path_type(path, FALSE, TRUE))
            return 0;
        if (spp_path_type(path, FALSE, FALSE))
            return spp_kernel_version(path, version, TRUE) ? (unsigned)wcstoul(version, NULL, 10) : 0;
    }
    return 0;
}

#include "ci_expiry.h"
#include "cert_patch.h"
#include "winload_modify.h"
#include "signer.h"
#include "slshim_install.h"
#include "wintrust_sign.h"
#include "wintrust_status.h"
#include "uiaccess.h"
#include "uac.h"
#include "mmc_approval.h"

static void suggest_ci(void)
{
    wprintf(L"For CI build-expiry restrictions, use nttimebomb /cishim OFFLINE_ROOT on a mounted or deployed offline Windows image.\n"
            L"/cishim has no build-number gate. The watermark remains.\n");
}

static BOOL rename_licensing_ui(const wchar_t *root, unsigned build)
{
    wchar_t path[PATH_SIZE], backup[PATH_SIZE];
    if (!build_path(path, root, L"Windows\\System32\\LicensingUI.exe") ||
        !build_path(backup, root, L"Windows\\System32\\LicensingUI.exe.bak") ||
        !spp_path_chain(path, FALSE) || !spp_path_type(path, FALSE, TRUE) ||
        !spp_path_type(backup, FALSE, TRUE))
        return FALSE;

    wprintf(L"Build %u: the normal image/SPP workflow only renames LicensingUI.exe.\n", build);
    if (!spp_path_type(path, FALSE, FALSE)) {
        wprintf(spp_path_type(backup, FALSE, FALSE) ? L"LicensingUI.exe is already renamed.\n" :
                                                   L"LicensingUI.exe is absent. No files changed.\n");
        suggest_ci();
        return TRUE;
    }
    if (spp_path_type(backup, FALSE, FALSE)) {
        fwprintf(stderr, L"Cannot rename LicensingUI.exe because %ls already exists.\n", backup);
        return FALSE;
    }
    HANDLE file = spp_open(path, DELETE, OPEN_EXISTING);
    BOOL ok = file != INVALID_HANDLE_VALUE && spp_rename(file, backup);
    if (!ok)
        fwprintf(stderr, L"Cannot rename %ls (Win32 %lu).\n", path, GetLastError());
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (ok) {
        wprintf(L"Renamed LicensingUI.exe to %ls.\n", backup);
        suggest_ci();
    }
    return ok;
}

typedef struct {
    BCRYPT_ALG_HANDLE algorithm;
    const wchar_t *boot, *recovery, *source;
    SppMode spp_mode;
    BOOL patch_boot, boot_wim, sku_spp;
} ImageOptions;

/* From this build on the FlightSigned token replacement no longer applies: those
   images need the CI and licensing work instead, and nothing is modified here. */
enum { LEGACY_BUILD_LIMIT = 15063 };

static void suggest_newer_modes(unsigned build)
{
    fwprintf(stderr,
             L"Build %u is 15063 or newer, so this mode does not apply and no file was\n"
             L"changed. Use nttimebomb /cishim OFFLINE_ROOT for the CI build-expiry\n"
             L"restrictions and nttimebomb /slshim OFFLINE_WINDOWS_ROOT for the licensing\n"
             L"side; both can be applied to the same image.\n", build);
}

static BOOL service_nt6(const wchar_t *source, const wchar_t *root)
{
    unsigned build = image_build(root, FALSE);
    if (build && build >= LEGACY_BUILD_LIMIT) {
        suggest_newer_modes(build);
        return FALSE;
    }
    return replace_nt6_tokens(source, root);
}

static BOOL service_image(const wchar_t *root, void *context)
{
    const ImageOptions *options = context;
    unsigned build = image_build(root, options->boot_wim);
    if (!build) {
        fwprintf(stderr, L"Cannot determine the Windows build in %ls.\n", root);
        return FALSE;
    }
    if (build >= LEGACY_BUILD_LIMIT) {
        suggest_newer_modes(build);
        return FALSE;
    }
    if (!options->patch_boot && !options->source) {
        fwprintf(stderr, L"/spponly requires /spp or /spp-reference.\n");
        return FALSE;
    }
    if (options->source && !replace_image_spp(options->source, root, TRUE, options->spp_mode, options->sku_spp))
        return FALSE;
    if (options->patch_boot &&
        !patch_offline_image(options->algorithm, root, options->boot, options->recovery, options->boot_wim))
        return FALSE;
    if (options->source && !replace_image_spp(options->source, root, FALSE, options->spp_mode, options->sku_spp)) {
        if (options->patch_boot)
            fwprintf(stderr, L"Offline boot updates completed before SPP failed. The SPP operation can be retried separately.\n");
        return FALSE;
    }

    return TRUE;
}

#include "media.h"
#include "bcd.h"

static int run_mmc(int argc, wchar_t **argv)
{
    if (argc != 2 || in_winpe()) {
        fwprintf(stderr, L"Use nttimebomb /mmc or /mmc-restore in the running test Windows after OOBE.\n");
        return 2;
    }
#if defined(__aarch64__)
    static const wchar_t name[] = L"nttimebomb-mmc-arm64.exe";
#elif defined(_WIN64)
    static const wchar_t name[] = L"nttimebomb-mmc-x64.exe";
#else
    static const wchar_t name[] = L"nttimebomb-mmc-x86.exe";
#endif
    wchar_t path[PATH_SIZE];
    DWORD length = GetModuleFileNameW(NULL, path, PATH_SIZE);
    wchar_t *leaf = length && length < PATH_SIZE ? wcsrchr(path, L'\\') : NULL;
    if (!leaf || (size_t)(leaf + 1 - path) + ARRAYSIZE(name) > PATH_SIZE) return 1;
    wcscpy(leaf + 1, name);
    if (!spp_path_type(path, FALSE, FALSE)) {
        fwprintf(stderr, L"Missing %ls. Extract the complete NT Timebomb Patch package.\n", path);
        return 1;
    }
    wchar_t command[64];
    swprintf(command, ARRAYSIZE(command), L"%ls %ls", name,
             !_wcsicmp(argv[1], L"/mmc") ? L"/mmc" : L"/mmc-restore");
    return run_tool(path, command, NULL) ? 0 : 1;
}

static int help(void)
{
    wprintf(L"NT Timebomb Patch " NTTP_VERSION_TEXT L"\n\n"
            L"Use an elevated command prompt for offline servicing. In WinPE use SYSTEM.\n"
            L"All paths must be local drive paths under MAX_PATH. Quote paths containing spaces.\n\n"
            L"EXPERIMENTAL COMPLETE WINDOWS LICENSING SHIM\n"
            L"  nttimebomb /slshim OFFLINE_WINDOWS_ROOT\n"
            L"  nttimebomb /slshim-restore OFFLINE_WINDOWS_ROOT\n"
            L"Explicitly replaces the target's licensing client DLLs, disables existing Windows\n"
            L"licensing services (including Vista SLSvc) and installs a dedicated LocalSystem\n"
            L"shim service. It uses that SKU's ProductPolicy, preserves DLL export names/ordinals\n"
            L"and validates known ABIs. Older policy expiry is removed before first boot.\n"
            L"Use the complete slshim/ and dependencies/ folders from this package. Backups\n"
            L"are retained in OFFLINE_ROOT\\NTTimebombBackup\\SLShim. Restore includes original\n"
            L"DLLs and permissions, SPP service settings and ProductPolicy; unrelated registry\n"
            L"changes are retained. This is a local licensing emulation, not a Microsoft digital\n"
            L"license or online activation. Unsupported licensing APIs return explicit errors.\n"
            L"This mode is never implied by /image, /spp, /nt6, /media or /cishim. It does not\n"
            L"change CI, boot files, kernels or LicensingUI. Apply /cishim separately if needed.\n\n"
            L"EXPERIMENTAL MMC CERTIFICATE EXPIRY EXCEPTION\n"
            L"  nttimebomb /mmc                  (deprecated, see CHANGELOG.md)\n"
            L"  nttimebomb /mmc-restore\n"
            L"Run as administrator inside the installed test Windows after OOBE. Requires a\n"
            L"matching original Microsoft catalog signature whose only trust error is expiry.\n"
            L"Adds a local embedded signature to native mmc.exe and keeps the original file.\n"
            L"Test the original MMC entry point and UAC prompt. /mmc-restore restores the\n"
            L"original executable and removes the local certificate.\n"
            L"  nttimebomb /mmc-approval [...]   (deprecated, see CHANGELOG.md)\n"
            L"  nttimebomb /mmc-approval-restore [OFFLINE_WINDOWS_ROOT]\n"
            L"Without a path, or with the running installation, AppInfo is in use: the replacement is\n"
            L"staged, applied at the next start, and keeps the original timestamps. A path on\n"
            L"another volume is edited in place. Unknown layouts are rejected.\n\n"
            L"CI BUILD-EXPIRY PATCH\n"
            L"  nttimebomb /cishim OFFLINE_ROOT|FOLDER|FILE\n"
            L"Example: nttimebomb /cishim D:\\mount\n"
            L"Processes System32\\ci.dll and the boot loaders: winload.efi, winresume.efi,\n"
            L"the legacy winload.exe and winresume.exe, and their System32\\Boot copies.\n"
            L"The loader part keeps only the explicit BCD nointegritychecks option. The\n"
            L"forced integrity option and the image-hash and catalog gates belong to\n"
            L"/winload-modify. A missing or unsupported UEFI or legacy loader stops the\n"
            L"operation before CI is written. Accepts a single extracted file or a folder.\n"
            L"Recognizes an ARM64 CI that already returns zero without changing the loader.\n"
            L"No build/version query is used.\n"
            L"Preview x64 expiry callbacks are identified structurally and return a zero expiry\n"
            L"time with success. Existing earlier x86/x64 FlightSigned CI rules are also accepted.\n"
            L"Unknown or ambiguous structures fail without writing. Native x86 newer preview\n"
            L"expiry callbacks are not yet verified; x86 hosts can service the x64 samples.\n"
            L"Backups beside each changed file use .bak and retain its permissions.\n"
            L"Existing backups are never overwritten. Retry recognizes already patched files.\n"
            L"The loader rejects the modified ci.dll with 0xc0000428 unless the target entry has\n"
            L"nointegritychecks on, with Secure Boot off. Add /bcd EFI_PARTITION to the command\n"
            L"(or run nttimebomb /bcd S:\\) before booting.\n"
            L"  nttimebomb /cishim-boot OFFLINE_ROOT|FOLDER|FILE [/bcd EFI_SYSTEM_PARTITION]\n"
            L"code of every step. Run it the second time after a start attempt to read the result.\n\n"
            L"  nttimebomb /bcd EFI_SYSTEM_PARTITION [ENTRY_GUID]\n"
            L"  nttimebomb /bcd-show EFI_SYSTEM_PARTITION [ENTRY_GUID]\n"
            L"  nttimebomb /bcd-template OFFLINE_WINDOWS_ROOT\n"
            L"Sets or prints nointegritychecks for the entry (default {default}) through bcdedit\n"
            L"against the offline BCD store. /cishim and /cishim-boot accept /bcd ESP to do the\n"
            L"same in one step.\n\n"
            L"RESTORE THE RETAINED ORIGINALS\n"
            L"  nttimebomb /restore OFFLINE_ROOT|FOLDER|FILE\n"
            L"Each changed file keeps a verified FILE.bak with its original owner, DACL and\n"
            L"attributes; older packages used FILE.nttp-original, which is also accepted.\n"
            L"Restore writes the original bytes back, re-applies the retained metadata,\n"
            L"verifies the result and removes that backup. Files without a retained\n"
            L"original are left alone.\n"
            L"  nttimebomb /cishim-restore ROOT|FOLDER|FILE        ci.dll and every loader\n"
            L"  nttimebomb /cishim-boot-restore ROOT|FOLDER|FILE   loaders only\n"
            L"  nttimebomb /winload-modify-restore ROOT|FOLDER|FILE  EFI and legacy loaders\n"
            L"Use /cishim-restore from WinPE to\n"
            L"undo a /cishim that does not boot.\n\n"
            L"NT6 TOKENS AND OPTIONAL BRANDING\n"
            L"  nttimebomb /nt6 /file DONOR_FOLDER /target OFFLINE_WINDOWS_ROOT\n"
            L"Copies only System32\\spp\\tokens from the donor. A donor may be its image root,\n"
            L"System32 folder, spp folder, or a folder named tokens. Existing extra tokens remain.\n"
            L"Grants NT SERVICE\\sppsvc full control on the target tokens tree, including existing\n"
            L"files and folders. If DONOR_FOLDER contains Branding (or Windows\\Branding), its\n"
            L"contents also update target Windows\\Branding with TrustedInstaller Full Control.\n"
            L"This detection is automatic, with no extra switch. Existing target-only files remain.\n"
            L"This mode changes only tokens and the optional Branding. The FlightSigned token\n"
            L"replacement applies below Build 15063 only; newer images are refused with a pointer\n"
            L"to /cishim and /slshim.\n\n"
            L"COMPLETE INSTALLATION MEDIA\n"
            L"  nttimebomb /media SOURCE_ISO_OR_FOLDER /work NEW_FOLDER /out NEW_ISO\n"
            L"    [/oscdimg OSCDIMG_EXE] [/7zip SEVENZIP_EXE] [/spp RTM_FOLDER]\n"
            L"  nttimebomb /media SOURCE /work NEW_FOLDER /out NEW_ISO /spponly RTM_FOLDER\n"
            L"  nttimebomb /media SOURCE /work NEW_FOLDER /out NEW_ISO /nt6 TOKENS_DONOR\n"
            L"With /spponly or /nt6, only all install.wim indexes are serviced. /nt6 also applies\n"
            L"optional Branding using the same automatic donor detection. boot.wim and\n"
            L"media-root boot files are preserved. Build 15063 and newer is refused without\n"
            L"changing anything and points at /cishim and /slshim instead.\n"
            L"Copies or extracts the source into a new workspace, services every boot.wim and\n"
            L"install.wim index, and patches the media-root bootmgr and bootmgr.efi.\n"
            L"Requires standalone sources\\boot.wim and sources\\install.wim plus BIOS/UEFI\n"
            L"El Torito files. Split WIMs and install.esd are not accepted. Optional /spp applies\n"
            L"to install.wim only. OSCDIMG builds a BIOS+UEFI ISO after servicing succeeds.\n"
            L"Provide OSCDIMG and (for ISO input) 7-Zip beside the executable, in PATH, or explicitly.\n"
            L"The new workspace remains available for inspection or manual cleanup after any result.\n\n"
            L"TWO STANDALONE BOOT MANAGERS\n"
            L"  nttimebomb /bootfiles INPUT_FOLDER /out NEW_FOLDER\n"
            L"Place bootmgr and bootmgr.efi together in INPUT_FOLDER. Both are verified before\n"
            L"the patched pair is written to a new folder. Deploy them to the matching media.\n\n"
            L"EXISTING OFFLINE MODES\n"
            L"  /image ROOT [/boot ESP] [/recovery ROOT] [/spp DONOR]\n"
            L"  /spponly ROOT /spp DONOR\n"
            L"  /spponly INPUT_WIM /out NEW_WIM /spp DONOR [/index N|all]\n"
            L"  /image ROOT /spponly /spp DONOR\n"
            L"/spponly replaces SPP below Build 15063, preserving boot files, CI, kernels and\n"
            L"LicensingUI. A donor is required. Build 15063 and newer is refused entirely. For\n"
            L"multi-index WIMs, shared spp*\n"
            L"and the SKU's *.cat files side by side. A CatRoot subfolder is optional.\n"
            L"Missing SKU folders or usable catalogs stop the operation.\n"
            L"  /bootwim EXTRACTED_ROOT\n"
            L"  /bootwim INPUT_WIM /out NEW_WIM [/index N]\n"
            L"Use /out with WIM input. /image and /spponly default to index 1; /index all selects\n"
            L"every index. /bootwim defaults to all indexes. Single-index WIMs and mounted roots\n"
            L"keep the original flat donor layout. SKU selection applies to standard /spp only.\n"
            L"From Build 15063 on, the image, SPP and NT6 workflows make no change at all and\n"
            L"ask for /cishim and /slshim instead. Restore and read-only commands\n"
            L"retain their scope. Read README.md for donor\n"
            L"layouts, SPP exclusions, restore examples, boot diagnostics, and known limitations.\n");
    return 0;
}

static int run_ci(int argc, wchar_t **argv)
{
    BOOL loader = !_wcsicmp(argv[1], L"/cishim-boot");
    const wchar_t *bcd = NULL;
    if (argc == 5 && !_wcsicmp(argv[3], L"/bcd"))
        bcd = argv[4];
    else if (argc != 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls OFFLINE_ROOT|FOLDER|FILE [/bcd EFI_SYSTEM_PARTITION]\n", argv[1]);
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    wchar_t esp[PATH_SIZE];
    if (bcd && !normalize(esp, bcd)) {
        fwprintf(stderr, L"Use a local drive path for the EFI System Partition.\n");
        return 2;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    BOOL ok = patch_ci_command(algorithm, argv[2], loader);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (ok && bcd && !bcd_set_nointegritychecks(esp, L"{default}"))
        ok = FALSE;
    return ok ? 0 : 1;
}

static int run_cert(int argc, wchar_t **argv)
{
    /* /wintrust is the one entry point: a path selects the image to service and a
       path inside the running installation uses the staged replacement. Without a
       path it always means the running installation. */
    BOOL restore = !_wcsicmp(argv[1], L"/wintrust-restore") ||
                   !_wcsicmp(argv[1], L"/wintrust-approval-restore");
    BOOL explicit_offline = !_wcsicmp(argv[1], L"/wintrust-approval") ||
                            !_wcsicmp(argv[1], L"/wintrust-approval-restore");
    if (argc > 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls [OFFLINE_ROOT|FOLDER|FILE]\n", argv[1]);
        return 2;
    }
    wchar_t path[PATH_SIZE];
    BOOL have_path = argc == 3;
    if (have_path && !normalize(path, argv[2])) {
        fwprintf(stderr, L"Use a local drive path.\n");
        return 2;
    }
    BOOL live = !have_path;
    if (have_path && !explicit_offline)
        live = wintrust_running(path);
    if (live) {
        if (in_winpe()) {
            fwprintf(stderr, L"Use /wintrust OFFLINE_ROOT from WinPE or another Windows installation.\n");
            return 2;
        }
        BCRYPT_ALG_HANDLE algorithm;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
            return 1;
        BOOL ok = wintrust_live(algorithm, restore);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return ok ? 0 : 1;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    BOOL ok = wintrust_offline(algorithm, path, restore);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}

static int run_winload(int argc, wchar_t **argv)
{
    wchar_t efi[PATH_SIZE], legacy[PATH_SIZE];
    if ((argc != 3 && argc != 4) || !normalize(efi, argv[2]) ||
        (argc == 4 && !normalize(legacy, argv[3]))) {
        fwprintf(stderr, L"Usage: nttimebomb %ls EFI_SYSTEM_PARTITION [LEGACY_VOLUME_OR_WINDOWS_ROOT]\n", argv[1]);
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    BOOL ok = patch_winload_modify(algorithm, efi, argc == 4 ? legacy : NULL);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}

static unsigned restore_set(const wchar_t *command)
{
    if (!_wcsicmp(command, L"/wintrust-restore"))
        return RESTORE_CERT;
    if (!_wcsicmp(command, L"/winload-modify-restore"))
        return RESTORE_LOADER;
    if (!_wcsicmp(command, L"/cishim-boot-restore"))
        return RESTORE_LOADER;
    if (!_wcsicmp(command, L"/cishim-restore"))
        return RESTORE_CI;
    return RESTORE_ALL;
}

static int run_restore(int argc, wchar_t **argv)
{
    if (argc != 3) {
        fwprintf(stderr, L"Usage: nttimebomb %ls OFFLINE_ROOT|FOLDER|FILE\n", argv[1]);
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") || !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    BOOL ok = patch_restore_command(algorithm, argv[2], restore_set(argv[1]));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}

static int run_new(int argc, wchar_t **argv)
{
    BOOL nt6 = FALSE;
    const wchar_t *donor_arg = NULL, *target_arg = NULL, *media_arg = NULL, *work_arg = NULL;
    const wchar_t *out_arg = NULL, *root_arg = NULL, *osc_arg = NULL, *zip_arg = NULL, *spp_arg = NULL;
    const wchar_t *spponly_arg = NULL;
    for (int i = 1; i < argc;) {
        const wchar_t *option = argv[i++];
        if (!_wcsicmp(option, L"/nt6")) {
            if (nt6)
                return 2;
            nt6 = TRUE;
            if (i < argc && argv[i][0] && argv[i][0] != L'/') {
                if (donor_arg)
                    return 2;
                donor_arg = argv[i++];
            }
            continue;
        }
        if (i == argc || !argv[i][0] || argv[i][0] == L'/')
            return 2;
        const wchar_t **slot;
        if (!_wcsicmp(option, L"/file"))
            slot = &donor_arg;
        else if (!_wcsicmp(option, L"/target"))
            slot = &target_arg;
        else if (!_wcsicmp(option, L"/media"))
            slot = &media_arg;
        else if (!_wcsicmp(option, L"/work"))
            slot = &work_arg;
        else if (!_wcsicmp(option, L"/out"))
            slot = &out_arg;
        else if (!_wcsicmp(option, L"/bootfiles"))
            slot = &root_arg;
        else if (!_wcsicmp(option, L"/oscdimg"))
            slot = &osc_arg;
        else if (!_wcsicmp(option, L"/7zip"))
            slot = &zip_arg;
        else if (!_wcsicmp(option, L"/spp"))
            slot = &spp_arg;
        else if (!_wcsicmp(option, L"/spponly"))
            slot = &spponly_arg;
        else
            return 2;
        if (*slot)
            return 2;
        *slot = argv[i++];
    }
    if (nt6 && (!donor_arg || root_arg || spp_arg || spponly_arg ||
        (media_arg ? target_arg || !work_arg || !out_arg : !target_arg || work_arg || out_arg || osc_arg || zip_arg)))
        return 2;
    if (!nt6 && (donor_arg || target_arg || (!!media_arg == !!root_arg) || !out_arg ||
        (spp_arg && spponly_arg) || (media_arg && !work_arg) ||
        (root_arg && (work_arg || osc_arg || zip_arg || spp_arg || spponly_arg))))
        return 2;
    BOOL nt6_target = nt6 && !media_arg;
    const wchar_t *media_donor = nt6 ? donor_arg : spponly_arg ? spponly_arg : spp_arg;
    wchar_t source[PATH_SIZE], target[PATH_SIZE], work[PATH_SIZE], output[PATH_SIZE], spp[PATH_SIZE];
    if (!normalize(source, nt6_target ? donor_arg : media_arg ? media_arg : root_arg) ||
        (target_arg && !normalize(target, target_arg)) ||
        (work_arg && !normalize(work, work_arg)) || (out_arg && !normalize(output, out_arg)) ||
        (media_donor && !normalize(spp, media_donor)))
        return 2;
    if ((nt6_target && !offline_root(target, TRUE)) ||
        !spp_path_chain(source, nt6_target || root_arg || !spp_ext(source, (const wchar_t *const[]){L".iso", NULL})))
        return 2;
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeBackupPrivilege") ||
        !enable_privilege(L"SeRestorePrivilege")) {
        privilege_hint();
        return 3;
    }
    if (nt6_target)
        return service_nt6(source, target) ? 0 : 1;
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    MediaMode mode = nt6 ? MEDIA_NT6 : spponly_arg ? MEDIA_SPP_ONLY : MEDIA_PATCH;
    ImageOptions options = {.algorithm = algorithm, .patch_boot = TRUE, .source = media_donor ? spp : NULL};
    BOOL ok = media_arg ? service_media(source, work, output, osc_arg, zip_arg, &options, mode) :
                          root_boot_files(algorithm, source, output);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok ? 0 : 1;
}

static int offline_usage(void)
{
    fwprintf(stderr, L"Usage: nttimebomb /image OFFLINE_ROOT [/boot BOOT_ROOT] [/recovery RECOVERY_ROOT] [/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT]\n"
                     L"       nttimebomb /cishim OFFLINE_ROOT\n"
                     L"       nttimebomb {/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT} /target OFFLINE_ROOT\n"
                     L"       nttimebomb /spp-restore CLEAN_IMAGE_ROOT /target OFFLINE_ROOT\n"
                     L"       nttimebomb /spp-restore ORIGINAL_FILE /target OFFLINE_ROOT /file WINDOWS_RELATIVE_PATH\n"
                     L"       nttimebomb /spponly OFFLINE_ROOT [/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT]\n"
                     L"       nttimebomb {/image | /spponly} INPUT_WIM /out OUTPUT_WIM [/index N|all] [SPP options]\n"
                     L"       nttimebomb /bootwim EXTRACTED_ROOT\n"
                     L"       nttimebomb /bootwim INPUT_WIM /out OUTPUT_WIM [/index N]\n");
    return 2;
}

static int run_offline(int argc, wchar_t **argv)
{
    const wchar_t *image_arg = NULL, *boot_arg = NULL, *recovery_arg = NULL;
    const wchar_t *source_arg = NULL, *target_arg = NULL, *file_arg = NULL;
    const wchar_t *wim_arg = NULL, *output_arg = NULL, *index_arg = NULL, *spponly_arg = NULL;
    BOOL spponly = FALSE;
    SppMode spp_mode = SPP_RTM;
    for (int i = 1; i < argc;) {
        const wchar_t *option = argv[i++];
        BOOL has_value = i < argc && argv[i][0] && argv[i][0] != L'/';
        if (!_wcsicmp(option, L"/spponly")) {
            if (spponly)
                return offline_usage();
            spponly = TRUE;
            if (has_value)
                spponly_arg = argv[i++];
            continue;
        }
        if (!has_value)
            return offline_usage();
        const wchar_t **argument;
        if (!_wcsicmp(option, L"/image"))
            argument = &image_arg;
        else if (!_wcsicmp(option, L"/boot"))
            argument = &boot_arg;
        else if (!_wcsicmp(option, L"/recovery"))
            argument = &recovery_arg;
        else if (!_wcsicmp(option, L"/bootwim"))
            argument = &wim_arg;
        else if (!_wcsicmp(option, L"/out"))
            argument = &output_arg;
        else if (!_wcsicmp(option, L"/index"))
            argument = &index_arg;
        else if (!_wcsicmp(option, L"/spp") || !_wcsicmp(option, L"/spp-reference") ||
                 !_wcsicmp(option, L"/spp-restore")) {
            argument = &source_arg;
            if (!_wcsicmp(option, L"/spp-restore"))
                spp_mode = SPP_RESTORE;
            else if (!_wcsicmp(option, L"/spp-reference"))
                spp_mode = SPP_REFERENCE;
        } else if (!_wcsicmp(option, L"/target"))
            argument = &target_arg;
        else if (!_wcsicmp(option, L"/file"))
            argument = &file_arg;
        else
            return offline_usage();
        if (*argument)
            return offline_usage();
        *argument = argv[i++];
    }
    BOOL boot_wim = wim_arg != NULL, image = image_arg || spponly_arg;
    BOOL patch_boot = (image && !spponly) || boot_wim;
    if ((spponly_arg && image_arg) || (spponly && !image) ||
        (boot_wim && (image || source_arg || target_arg || boot_arg || recovery_arg || file_arg)) ||
        (file_arg && spp_mode != SPP_RESTORE) ||
        (image && (target_arg || spp_mode == SPP_RESTORE)) ||
        ((!image || spponly) && (boot_arg || recovery_arg)) ||
        (!image && !boot_wim && (!source_arg || !target_arg)))
        return offline_usage();

    const wchar_t *input = boot_wim ? wim_arg : image_arg ? image_arg : spponly_arg ? spponly_arg : target_arg;
    wchar_t target[PATH_SIZE], boot[PATH_SIZE], recovery[PATH_SIZE], source[PATH_SIZE], output[PATH_SIZE];
    if (!normalize(target, input) ||
        (boot_arg && !normalize(boot, boot_arg)) || (recovery_arg && !normalize(recovery, recovery_arg)) ||
        (source_arg && !normalize(source, source_arg)) || (output_arg && !normalize(output, output_arg))) {
        fwprintf(stderr, L"Use local drive paths under MAX_PATH.\n");
        return 2;
    }
    BOOL raw_wim = (image || boot_wim) && spp_ext(target, (const wchar_t *const[]){L".wim", NULL});
    DWORD first = 1, last = 1, count = 0;
    if (raw_wim) {
        count = wim_image_count(target);
        if (!output_arg || boot_arg || recovery_arg)
            return offline_usage();
        if (!count) {
            fwprintf(stderr, L"Cannot read a standalone WIM: %ls.\n", target);
            return 1;
        }
        last = boot_wim ? count : 1;
        if (index_arg && !_wcsicmp(index_arg, L"all")) {
            last = count;
        } else if (index_arg) {
            wchar_t *end;
            first = wcstoul(index_arg, &end, 10);
            if (*end || wcsspn(index_arg, L"0123456789") != wcslen(index_arg) ||
                !first || first > count || first == MAXDWORD)
                return offline_usage();
            last = first;
        }
    } else if (output_arg || index_arg) {
        return offline_usage();
    } else if (!offline_root(target, !boot_wim)) {
        fwprintf(stderr, L"Specify an offline Windows root, an extracted boot image, or a WIM with /out.\n");
        return 2;
    }
    if ((in_winpe() && !is_system()) || !enable_privilege(L"SeRestorePrivilege") ||
        !enable_privilege(L"SeBackupPrivilege")) {
        privilege_hint();
        return 3;
    }
    if (file_arg) {
        if (restore_spp_file(source, target, file_arg))
            return 0;
        fwprintf(stderr, L"Single-file restore requires an original SPP file and a safe path such as Windows\\System32\\sppc.dll.\n");
        return 1;
    }
    if (spp_mode == SPP_RESTORE)
        return replace_spp(source, target, FALSE, spp_mode) ? 0 : 1;

    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) {
        fwprintf(stderr, L"Could not initialize the Windows SHA-256 provider.\n");
        return 1;
    }
    ImageOptions options = {
        .algorithm = algorithm, .boot = boot_arg ? boot : NULL, .recovery = recovery_arg ? recovery : NULL,
        .source = source_arg ? source : NULL, .spp_mode = spp_mode, .patch_boot = patch_boot, .boot_wim = boot_wim,
        .sku_spp = raw_wim && count > 1
    };
    BOOL ok = raw_wim ? edit_wim(target, output, first, last, service_image, &options) :
                        service_image(target, &options);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok)
        privilege_hint();
    return ok ? 0 : 1;
}

static BOOL boot_report_file(BCRYPT_ALG_HANDLE algorithm, const wchar_t *root, const wchar_t *relative,
                             Role role, BOOL *found)
{
    wchar_t path[PATH_SIZE], version[24];
    *found = FALSE;
    if (!build_path(path, root, relative) || !spp_path_chain(path, FALSE) ||
        !spp_path_type(path, FALSE, TRUE)) {
        fwprintf(stderr, L"Cannot inspect %ls under %ls.\n", relative, root);
        return FALSE;
    }
    if (!spp_path_type(path, FALSE, FALSE)) {
        wprintf(L"%ls: absent\n", path);
        return TRUE;
    }
    HANDLE file = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    Output original = {0};
    BOOL ok = file != INVALID_HANDLE_VALUE && offline_read(file, &original, algorithm);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (!ok) {
        fwprintf(stderr, L"Cannot read %ls.\n", path);
    } else {
        *found = TRUE;
        WORD architecture = spp_pe_machine(path), patched_machine;
        BOOL changed;
        wprintf(L"%ls\n  Version: %ls  PE machine: 0x%04X\n  On-disk SHA-256: %hs\n", path,
                spp_kernel_version(path, version, FALSE) ? version : L"unknown", architecture, original.sha);
        BOOL recognized = patch_pe(original.data, original.size, role, &patched_machine, &changed);
        wprintf(L"  NT Timebomb Patch: %ls\n", !recognized ? L"no recognized patch structure" :
                changed ? L"matching rules would change this file" : L"recognized rules already applied");
    }
    free(original.data);
    return ok;
}

static int check_boot(int argc, wchar_t **argv)
{
    wchar_t root[PATH_SIZE], esp[PATH_SIZE];
    if (argc != 4 || !normalize(root, argv[2]) || !normalize(esp, argv[3]) ||
        !spp_path_chain(root, TRUE) || !spp_path_chain(esp, TRUE)) {
        fwprintf(stderr, L"Usage: nttimebomb check-boot OFFLINE_WINDOWS_ROOT EFI_SYSTEM_PARTITION\n");
        return 2;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
        return 1;
    static const struct { const wchar_t *path; Role role; BOOL on_esp; } files[] = {
        {L"Windows\\System32\\winload.efi", LOADER, FALSE},
        {L"Windows\\System32\\Boot\\winload.efi", LOADER, FALSE},
        {L"Windows\\Boot\\EFI\\bootmgfw.efi", BOOT, FALSE},
        {L"EFI\\Microsoft\\Boot\\bootmgfw.efi", BOOT, TRUE},
        {L"EFI\\Microsoft\\Boot\\bootmgr.efi", BOOT, TRUE},
        {L"EFI\\Boot\\bootx64.efi", BOOT, TRUE},
        {L"EFI\\Boot\\bootia32.efi", BOOT, TRUE}
    };
    BOOL ok = TRUE, loader = FALSE, manager = FALSE;
    for (unsigned i = 0; i < sizeof files / sizeof files[0]; ++i) {
        BOOL found;
        if (!boot_report_file(algorithm, files[i].on_esp ? esp : root, files[i].path, files[i].role, &found))
            ok = FALSE;
        if (i == 0)
            loader = found;
        if (files[i].on_esp)
            manager |= found;
    }
    BCryptCloseAlgorithmProvider(algorithm, 0);
    wprintf(L"Read-only report. Verify the active EFI path and VHDX entry separately with BCDEdit.\n");
    return ok && loader && manager ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && (!_wcsicmp(argv[1], L"--version") || !_wcsicmp(argv[1], L"/version"))) {
        wprintf(L"NT Timebomb Patch " NTTP_VERSION_TEXT L"\n");
        return 0;
    }
    if (argc >= 2 && (!_wcsicmp(argv[1], L"/mmc") || !_wcsicmp(argv[1], L"/mmc-restore")))
        return run_mmc(argc, argv);
            if (argc >= 2 && (!_wcsicmp(argv[1], L"/mmc-approval") || !_wcsicmp(argv[1], L"/mmc-approval-restore")))
        return run_mmc_approval(argc, argv);
    if(argc>=2 && (!_wcsicmp(argv[1],L"/slshim") || !_wcsicmp(argv[1],L"/slshim-restore")))
        return run_slshim(argc,argv);
    if (argc >= 2 && (!_wcsicmp(argv[1], L"/cishim") || !_wcsicmp(argv[1], L"/cishim-boot")))
        return run_ci(argc, argv);
            if (argc >= 2 && !_wcsicmp(argv[1], L"/wintrust-status")) {
        BCRYPT_ALG_HANDLE algorithm;
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0)
            return 1;
        int result = run_wintrust_status(algorithm, argc, argv);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return result;
    }
    /* /wintrust, /wintrust-restore, /wintrust-approval and /wintrust-approval-restore
       are implemented below but no longer dispatched: replacing the certificate
       modules is too easy to mis-sequence with the other live operations, and that
       produced unbootable installations. The code is kept for reference. */
    if (argc >= 2 && !_wcsicmp(argv[1], L"/winload-modify"))
        return run_winload(argc, argv);
    if (argc >= 2 && (!_wcsicmp(argv[1], L"/bcd") || !_wcsicmp(argv[1], L"/bcd-show")))
        return run_bcd(argc, argv);
    if (argc >= 2 && !_wcsicmp(argv[1], L"/bcd-template")) {
        if (argc != 3) {
            fwprintf(stderr, L"Usage: nttimebomb /bcd-template OFFLINE_ROOT\n");
            return 2;
        }
        return bcd_template(argv[2]) ? 0 : 1;
    }
    if (argc >= 2 && (!_wcsicmp(argv[1], L"/restore") || !_wcsicmp(argv[1], L"/cishim-restore") ||
                      !_wcsicmp(argv[1], L"/cishim-boot-restore") || !_wcsicmp(argv[1], L"/winload-modify-restore")))
        return run_restore(argc, argv);
    if (argc == 1 || (argc == 2 && (!_wcsicmp(argv[1], L"/?") || !_wcsicmp(argv[1], L"/help") ||
                                   !_wcsicmp(argv[1], L"--help"))))
        return help();
    for (int i = 1; i < argc; ++i)
        if (!_wcsicmp(argv[i], L"/nt6") || !_wcsicmp(argv[i], L"/media") || !_wcsicmp(argv[i], L"/bootfiles")) {
            int result = run_new(argc, argv);
            if (result == 2)
                fwprintf(stderr, L"Invalid arguments. Run nttimebomb /help for detailed instructions.\n");
            return result;
        }
    if (argc >= 2 && argv[1][0] == L'/')
        return run_offline(argc, argv);
    if (argc >= 2 && !_wcsicmp(argv[1], L"check-boot"))
        return check_boot(argc, argv);
    BOOL hvloader = argc >= 2 && (!_wcsicmp(argv[1], L"check-hvloader") ||
                                  !_wcsicmp(argv[1], L"patch-hvloader"));
    BOOL winre = argc == 4 && !_wcsicmp(argv[1], L"patch-winre");
    BOOL winre_check = argc == 3 && !_wcsicmp(argv[1], L"check-winre-mount");
    BOOL image = argc >= 2 && (!_wcsicmp(argv[1], L"check-image") ||
                              !_wcsicmp(argv[1], L"patch-image"));
    BOOL patch = argc == 4 && (!_wcsicmp(argv[1], L"patch") ||
                              !_wcsicmp(argv[1], L"patch-image") ||
                              !_wcsicmp(argv[1], L"patch-hvloader") || winre);
    BOOL check = argc == 3 && (!_wcsicmp(argv[1], L"check") ||
                              !_wcsicmp(argv[1], L"check-image") ||
                              !_wcsicmp(argv[1], L"check-hvloader") || winre_check);
    if (!patch && !check) {
        fwprintf(stderr, L"Usage: nttimebomb check[-image] INPUT_DIR\n"
                         L"       nttimebomb patch[-image] INPUT_DIR NEW_OUTPUT_DIR\n"
                         L"       nttimebomb check-hvloader INPUT_DIR\n"
                         L"       nttimebomb patch-hvloader INPUT_DIR NEW_OUTPUT_DIR\n"
                         L"       nttimebomb check-winre-mount MOUNT_DIR\n"
                         L"       nttimebomb patch-winre INPUT_WIM NEW_OUTPUT_WIM\n"
                         L"       nttimebomb check-boot OFFLINE_WINDOWS_ROOT EFI_SYSTEM_PARTITION\n");
        return offline_usage();
    }
    if (patch && in_winpe() && !is_system()) {
        fwprintf(stderr, L"WinPE writes require a LocalSystem (S-1-5-18) command prompt.\n");
        privilege_hint();
        return 3;
    }

    wchar_t input[PATH_SIZE], output[PATH_SIZE];
    if (!normalize(input, argv[2]) || (patch && !normalize(output, argv[3]))) {
        fwprintf(stderr, L"Use local drive paths under MAX_PATH.\n");
        return 2;
    }
    BCRYPT_ALG_HANDLE algorithm;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0) < 0) {
        fwprintf(stderr, L"Could not initialize the Windows SHA-256 provider.\n");
        return 1;
    }
    if (winre || winre_check) {
        BOOL ok = winre ? patch_winre(algorithm, input, output) : scan_winre(algorithm, input, FALSE);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return ok ? 0 : 1;
    }
    Output images[FILE_COUNT] = {0};
    BOOL ok = TRUE;
    unsigned first = hvloader ? HV_FIRST : 0;
    unsigned limit = hvloader ? FILE_COUNT : HV_FIRST;
    for (unsigned i = first; i < limit; ++i)
        if (!prepare(algorithm, input, &files[i], image, &images[i]))
            ok = FALSE;
    if (ok && hvloader && !images[HV_FIRST].data && !images[HV_FIRST + 1].data) {
        fwprintf(stderr, L"Provide hvloader.efi and/or hvloader.exe in the input directory.\n");
        ok = FALSE;
    }
    if (ok && !hvloader) {
        BOOL uefi = images[2].data && images[5].data;
        BOOL bios = images[7].data && images[9].data;
        BOOL any_uefi = images[2].data || images[3].data || images[4].data || images[5].data || images[6].data;
        BOOL any_bios = images[7].data || images[8].data || images[9].data || images[10].data;
        if ((!uefi && !bios) || (any_uefi && !uefi) || (any_bios && !bios)) {
            fwprintf(stderr, L"Provide complete boot pairs: bootmgfw.efi + winload.efi and/or bootmgr + winload.exe.\n");
            ok = FALSE;
        }
        for (unsigned i = 1; i < HV_FIRST; ++i) {
            if (images[i].data && i != 7 && i != 8 && images[i].machine != images[0].machine) {
                fwprintf(stderr, L"%ls has a different target architecture from ci.dll.\n", files[i].name);
                ok = FALSE;
            }
        }
        if (ok)
            wprintf(L"Target %ls. Boot paths:%ls%ls. Kernel expiration patch: %ls.\n",
                    images[0].machine == IMAGE_FILE_MACHINE_AMD64 ? L"x64" : L"x86",
                    uefi ? L" UEFI" : L"", bios ? L" Legacy" : L"",
                    images[1].data ? L"verified" : L"ntoskrnl.exe absent");
    }

    if (ok && patch)
        ok = write_output(output, images, algorithm);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    for (unsigned i = 0; i < FILE_COUNT; ++i)
        free(images[i].data);
    if (!ok)
        return 1;
    if (patch)
        wprintf(L"Verified copies saved in %ls.\n", output);
    return 0;
}


