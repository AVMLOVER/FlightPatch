#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

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
    BOOL pe64 = machine == IMAGE_FILE_MACHINE_AMD64 && magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
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

static BOOL rename_licensing_ui(const wchar_t *root, unsigned build)
{
    wchar_t path[PATH_SIZE], backup[PATH_SIZE];
    if (!build_path(path, root, L"Windows\\System32\\LicensingUI.exe") ||
        !build_path(backup, root, L"Windows\\System32\\LicensingUI.exe.bak") ||
        !spp_path_chain(path, FALSE) || !spp_path_type(path, FALSE, TRUE) ||
        !spp_path_type(backup, FALSE, TRUE))
        return FALSE;

    wprintf(L"Build %u: newer preview expiration uses a popup and watermark instead of the legacy FlightSigned restart or boot block.\n"
            L"Expiry may still prevent MMC and Windows Defender from running. The watermark remains.\n", build);
    if (!spp_path_type(path, FALSE, FALSE)) {
        wprintf(spp_path_type(backup, FALSE, FALSE) ? L"LicensingUI.exe is already renamed.\n" :
                                                   L"LicensingUI.exe is absent. No files changed.\n");
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
    if (ok)
        wprintf(L"Renamed LicensingUI.exe to %ls.\n", backup);
    return ok;
}

typedef struct {
    BCRYPT_ALG_HANDLE algorithm;
    const wchar_t *boot, *recovery, *source;
    SppMode spp_mode;
    BOOL patch_boot, boot_wim;
} ImageOptions;

static BOOL service_image(const wchar_t *root, void *context)
{
    const ImageOptions *options = context;
    unsigned build = image_build(root, options->boot_wim);
    if (!build) {
        fwprintf(stderr, L"Cannot determine the Windows build in %ls.\n", root);
        return FALSE;
    }
    if (build >= 15058)
        return rename_licensing_ui(root, build);
    if (!options->patch_boot && !options->source) {
        fwprintf(stderr, L"For builds below 15058, /spponly requires /spp or /spp-reference.\n");
        return FALSE;
    }
    if (options->source && !replace_spp(options->source, root, TRUE, options->spp_mode))
        return FALSE;
    if (options->patch_boot &&
        !patch_offline_image(options->algorithm, root, options->boot, options->recovery, options->boot_wim))
        return FALSE;
    if (options->source && !replace_spp(options->source, root, FALSE, options->spp_mode)) {
        if (options->patch_boot)
            fwprintf(stderr, L"Offline boot updates completed before SPP failed. The SPP operation can be retried separately.\n");
        return FALSE;
    }
    return TRUE;
}

static int offline_usage(void)
{
    fwprintf(stderr, L"Usage: flightpatch /image OFFLINE_ROOT [/boot BOOT_ROOT] [/recovery RECOVERY_ROOT] [/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT]\n"
                     L"       flightpatch {/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT} /target OFFLINE_ROOT\n"
                     L"       flightpatch /spp-restore CLEAN_IMAGE_ROOT /target OFFLINE_ROOT\n"
                     L"       flightpatch /spp-restore ORIGINAL_FILE /target OFFLINE_ROOT /file WINDOWS_RELATIVE_PATH\n"
                     L"       flightpatch /spponly OFFLINE_ROOT [/spp RTM_FOLDER | /spp-reference REFERENCE_ROOT]\n"
                     L"       flightpatch {/image | /spponly} INPUT_WIM /out OUTPUT_WIM [/index N] [SPP options]\n"
                     L"       flightpatch /bootwim EXTRACTED_ROOT\n"
                     L"       flightpatch /bootwim INPUT_WIM /out OUTPUT_WIM [/index N]\n");
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
    DWORD first = 1, last = 1;
    if (raw_wim) {
        DWORD count = wim_image_count(target);
        if (!output_arg || boot_arg || recovery_arg)
            return offline_usage();
        if (!count) {
            fwprintf(stderr, L"Cannot read a standalone WIM: %ls.\n", target);
            return 1;
        }
        last = boot_wim ? count : 1;
        if (index_arg) {
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
        .source = source_arg ? source : NULL, .spp_mode = spp_mode, .patch_boot = patch_boot, .boot_wim = boot_wim
    };
    BOOL ok = raw_wim ? edit_wim(target, output, first, last, service_image, &options) :
                        service_image(target, &options);
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (!ok)
        privilege_hint();
    return ok ? 0 : 1;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc >= 2 && argv[1][0] == L'/')
        return run_offline(argc, argv);
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
        fwprintf(stderr, L"Usage: flightpatch check[-image] INPUT_DIR\n"
                         L"       flightpatch patch[-image] INPUT_DIR NEW_OUTPUT_DIR\n"
                         L"       flightpatch check-hvloader INPUT_DIR\n"
                         L"       flightpatch patch-hvloader INPUT_DIR NEW_OUTPUT_DIR\n"
                         L"       flightpatch check-winre-mount MOUNT_DIR\n"
                         L"       flightpatch patch-winre INPUT_WIM NEW_OUTPUT_WIM\n");
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
