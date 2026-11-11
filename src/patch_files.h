/* Shared offline patch engine. Every target is opened, structurally matched and
   prepared in memory before the first write. Changed files are backed up beside
   themselves as .nttp-original with their permissions, locked, then written and
   verified. A write failure restores the original bytes.
   Used by /cishim, /cishim-boot, /wintrust and /winload-modify. */

typedef struct {
    wchar_t allow_final[OFFLINE_NT_PATH];
    wchar_t live_final[OFFLINE_NT_PATH];
    wchar_t live[PATH_SIZE];
    BY_HANDLE_FILE_INFORMATION live_dir;
} PatchScope;

typedef BOOL (*PatchPlan)(const Image *im, Plan *plan);

/* A build hook rewrites the prepared image in memory (size may shrink); a post
   hook runs after the file was written, for example to sign it in place. Both
   are optional. */
typedef BOOL (*PatchBuild)(BCRYPT_ALG_HANDLE algorithm, Output *after, void *context);
typedef BOOL (*PatchPost)(BCRYPT_ALG_HANDLE algorithm, OfflineEdit *edit, void *context);
/* Optional structural "already done" test, used by modes whose output cannot be
   reproduced byte for byte (a new signature is embedded on every run). */
typedef BOOL (*PatchRecognized)(const wchar_t *path, void *context);

enum { PATCH_READY = 1, PATCH_ABSENT = 0, PATCH_ERROR = -1 };

static BOOL ci_io_error(const wchar_t *action, const wchar_t *path, DWORD error)
{
    fwprintf(stderr, L"Cannot %ls %ls (Win32 %lu).\n", action, path, error);
    if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
        privilege_hint();
    return FALSE;
}

static BOOL ci_check_live_file(const OfflineEdit *edit, const wchar_t *live, const wchar_t *name,
                               const BY_HANDLE_FILE_INFORMATION *live_dir)
{
    /* A single link outside the live tree, or a different volume, rules out an alias.
       WinPE does not always have this boot file at the live System32 path. */
    if (edit->id.nNumberOfLinks == 1 || edit->id.dwVolumeSerialNumber != live_dir->dwVolumeSerialNumber)
        return TRUE;

    wchar_t relative[48], path[PATH_SIZE];
    BOOL wow = FALSE;
    BOOL native_path = sizeof(void *) == 4 && IsWow64Process(GetCurrentProcess(), &wow) && wow;
    if (swprintf(relative, 48, L"%ls\\%ls", native_path ? L"Sysnative" : L"System32", name) < 0 ||
        !build_path(path, live, relative))
        return ci_io_error(L"resolve the live file to compare with", edit->path, ERROR_FILENAME_EXCED_RANGE);
    HANDLE current = spp_open(path, FILE_READ_ATTRIBUTES, OPEN_EXISTING);
    if (current == INVALID_HANDLE_VALUE)
        return ci_io_error(L"check the live file for a hard link", path, GetLastError());
    BY_HANDLE_FILE_INFORMATION id;
    BOOL inspected = GetFileInformationByHandle(current, &id);
    DWORD error = GetLastError();
    CloseHandle(current);
    if (!inspected)
        return ci_io_error(L"read the identity of", path, error);
    if (offline_file_id(&edit->id, &id)) {
        fwprintf(stderr, L"Target is a hard link to the running Windows file %ls.\n", path);
        return FALSE;
    }
    return TRUE;
}

/* Backups created by this version use a .bak suffix. A backup written by an
   earlier package keeps its .nttp-original name and is still recognized. */
static BOOL ci_backup_name(const wchar_t *path, wchar_t backup[PATH_SIZE], const wchar_t *suffix)
{
    return swprintf(backup, PATH_SIZE, L"%ls%ls", path, suffix) >= 0;
}

static BOOL ci_find_backup(const wchar_t *path, wchar_t backup[PATH_SIZE])
{
    if (!ci_backup_name(path, backup, L".bak"))
        return FALSE;
    if (GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    if (!ci_backup_name(path, backup, L".nttp-original"))
        return FALSE;
    return GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES;
}

static BOOL ci_original_backup(OfflineEdit *edit, BCRYPT_ALG_HANDLE algorithm)
{
    wchar_t path[PATH_SIZE];
    if (!ci_find_backup(edit->path, path) && !ci_backup_name(edit->path, path, L".bak"))
        return FALSE;
    HANDLE backup = spp_open(path, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, CREATE_NEW);
    if (backup == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
            return ci_io_error(L"create backup", path, error);
        backup = spp_open(path, GENERIC_READ, OPEN_EXISTING);
        if (backup == INVALID_HANDLE_VALUE)
            return ci_io_error(L"open existing backup", path, GetLastError());
        Output original = {0};
        const char *expected = edit->base_sha[0] ? edit->base_sha : edit->before.sha;
        BOOL ok = offline_read(backup, &original, algorithm) && !strcmp(original.sha, expected);
        free(original.data);
        CloseHandle(backup);
        if (!ok)
            fwprintf(stderr, L"Existing backup differs from the unpatched input: %ls. Preserve it separately before retrying.\n", path);
        return ok;
    }
    LARGE_INTEGER start = {0};
    BOOL ok = SetFilePointerEx(edit->file, start, NULL, FILE_BEGIN) &&
              spp_copy_verified(edit->file, backup) && spp_restore_metadata(edit->file, backup) == ERROR_SUCCESS;
    CloseHandle(backup);
    if (!ok)
        DeleteFileW(path);
    else
        wprintf(L"Original file and permissions retained at %ls.\n", path);
    return ok;
}

static BOOL patch_scope_init(PatchScope *scope, const wchar_t *allow_root)
{
    UINT length = GetSystemWindowsDirectoryW(scope->live, PATH_SIZE);
    return length && length < PATH_SIZE && offline_directory(allow_root, scope->allow_final) &&
           offline_directory_info(scope->live, scope->live_final, &scope->live_dir);
}

static WORD image_machine_hint(const BYTE *data, DWORD size)
{
    if (size < 0x40 || memcmp(data, "MZ", 2))
        return 0;
    uint32_t pe;
    memcpy(&pe, data + 0x3c, sizeof pe);
    if (pe > size - 6)
        return 0;
    uint16_t machine;
    memcpy(&machine, data + pe + 4, sizeof machine);
    return machine;
}

static void patch_edit_release(OfflineEdit *edit)
{
    if (edit->file != INVALID_HANDLE_VALUE && edit->file)
        CloseHandle(edit->file);
    free(edit->after.data);
    free(edit->before.data);
    memset(edit, 0, sizeof *edit);
    edit->file = INVALID_HANDLE_VALUE;
}

/* Verify that the current file is the retained original with any subset of the
   complete edit set applied. This lets a newer build finish a patch that an
   earlier build left partially applied. */
static BOOL patch_subset_matches(BCRYPT_ALG_HANDLE algorithm, const Output *current, const Output *base,
                                 const Plan *edits)
{
    if (current->size != base->size || !current->size)
        return FALSE;
    BYTE *candidate = malloc(base->size);
    if (!candidate)
        return FALSE;
    memcpy(candidate, base->data, base->size);
    for (unsigned i = 0; i < edits->count; ++i) {
        const Change *change = &edits->edits[i];
        if (change->at + change->length > base->size)
            continue;
        if (!memcmp(current->data + change->at, change->bytes, change->length))
            memcpy(candidate + change->at, change->bytes, change->length);
    }
    /* Every patched file was closed with a valid PE checksum, so the candidate
       must be checksummed the same way before comparing. */
    BOOL ok = fix_checksum(candidate, base->size);
    char sha[65];
    ok = ok && digest(algorithm, candidate, base->size, sha) && !strcmp(sha, current->sha);
    free(candidate);
    return ok;
}

/* Build the patched contents from a base image and its edit plan. */
static BOOL patch_build_after(BCRYPT_ALG_HANDLE algorithm, const Output *base, const Plan *edits,
                              const Image *image, Output *after, BOOL *changed)
{
    after->size = base->size;
    after->data = malloc(after->size);
    if (!after->data)
        return FALSE;
    memcpy(after->data, base->data, after->size);
    for (unsigned i = 0; i < edits->count; ++i) {
        const Change *change = &edits->edits[i];
        memcpy(after->data + change->at, change->bytes, change->length);
    }
    if (edits->count && (!fix_checksum(after->data, after->size) ||
                         !digest(algorithm, after->data, after->size, after->sha)))
        return FALSE;
    if (!edits->count)
        memcpy(after->sha, base->sha, sizeof after->sha);
    after->machine = image->machine;
    *changed = edits->count != 0;
    return TRUE;
}

/* Queue one replacement for the next start. The single call writes the replace
   form of the pending-rename entry, so a failed rename can never leave the target
   missing. */
static BOOL patch_schedule_replace(const wchar_t *source, const wchar_t *target)
{
    if (MoveFileExW(source, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT))
        return TRUE;
    fwprintf(stderr, L"Cannot schedule the replacement of %ls with %ls (Win32 %lu).\n",
             target, source, GetLastError());
    return FALSE;
}

/* Count queued entries that reference one marker path. */
static unsigned patch_pending_count(const wchar_t *marker)
{
    HKEY key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                      0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
        return 0;
    DWORD type = 0, size = 0;
    unsigned count = 0;
    if (RegQueryValueExW(key, L"PendingFileRenameOperations", NULL, &type, NULL, &size) == ERROR_SUCCESS &&
        size >= 2 * sizeof(wchar_t)) {
        wchar_t *data = malloc(size + sizeof(wchar_t));
        if (data &&
            RegQueryValueExW(key, L"PendingFileRenameOperations", NULL, &type, (BYTE *)data, &size) == ERROR_SUCCESS) {
            unsigned wchars = size / sizeof(wchar_t);
            data[wchars - 1] = L'\0';
            for (unsigned i = 0; i < wchars && data[i];) {
                if (wcsstr(data + i, marker))
                    ++count;
                i += (unsigned)wcslen(data + i) + 1;
            }
        }
        free(data);
    }
    RegCloseKey(key);
    return count;
}

/* Some operations are only applied at the next start. Starting a second one on top
   of a pending journal interleaves two queues, and a partly applied set is what
   leaves the installation unable to start. Refuse until the pending one is done. */
static BOOL patch_live_guard(const wchar_t *self)
{
    static const wchar_t *const journals[] = {
        L"SOFTWARE\\NTTimebombPatch\\Wintrust",
        L"SOFTWARE\\NTTimebombPatch\\MMCApproval",
        L"SOFTWARE\\NTTimebombPatch\\MMC",
        L"SOFTWARE\\NTTimebombPatch\\MMCEmbedded"
    };
    for (unsigned i = 0; i < ARRAYSIZE(journals); ++i) {
        HKEY key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, journals[i], 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
            continue;
        RegCloseKey(key);
        fwprintf(stderr, L"An operation is already recorded at %ls and is applied at the next start.\n"
                         L"Restart first, then run %ls. Two pending operations at once can leave the\n"
                         L"installation unable to start.\n", journals[i], self);
        return FALSE;
    }
    return TRUE;
}

/* Give a file back the timestamps it had before this package rewrote it. */
static BOOL patch_keep_times(const wchar_t *path, const FILETIME *created, const FILETIME *accessed,
                             const FILETIME *written)
{
    HANDLE file = spp_open(path, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    BOOL ok = SetFileTime(file, created, accessed, written) != 0;
    DWORD error = GetLastError();
    CloseHandle(file);
    SetLastError(error);
    return ok;
}

/* Keep a copy next to a file that this mode does not change, so every target of an
   operation has a retained original and the restore path covers it too. */
static BOOL patch_retain_copy(const wchar_t *path)
{
    wchar_t backup[PATH_SIZE];
    if (swprintf(backup, PATH_SIZE, L"%ls.bak", path) < 0)
        return FALSE;
    if (GetFileAttributesW(backup) != INVALID_FILE_ATTRIBUTES)
        return TRUE;
    HANDLE source = spp_open(path, GENERIC_READ, OPEN_EXISTING);
    HANDLE copy = CreateFileW(backup, GENERIC_READ | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER, 0, NULL,
                              CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (copy == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED)
        copy = CreateFileW(backup, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok = source != INVALID_HANDLE_VALUE && copy != INVALID_HANDLE_VALUE &&
              spp_copy_verified(source, copy) && FlushFileBuffers(copy);
    if (ok && spp_restore_metadata(source, copy) != ERROR_SUCCESS)
        wprintf(L"%ls: the retained copy keeps the timestamps only (Win32 %lu).\n", backup, GetLastError());
    if (source != INVALID_HANDLE_VALUE)
        CloseHandle(source);
    if (copy != INVALID_HANDLE_VALUE)
        CloseHandle(copy);
    if (!ok) {
        DeleteFileW(backup);
        return FALSE;
    }
    return TRUE;
}

/* Prepare one file: resolve, verify scope, read, structurally match and build the
   patched contents in memory. Nothing is written here. */
static int patch_edit_prepare(BCRYPT_ALG_HANDLE algorithm, const PatchScope *scope,
                              const wchar_t *path, const wchar_t *name, BOOL required,
                              BOOL optional_structure, PatchPlan plan, PatchBuild build,
                              PatchRecognized recognized, void *context, OfflineEdit *edit)
{
    memset(edit, 0, sizeof *edit);
    edit->file = INVALID_HANDLE_VALUE;
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        if (required) {
            fwprintf(stderr, L"Missing required file %ls.\n", path);
            return PATCH_ERROR;
        }
        return PATCH_ABSENT;
    }
    if (!spp_path_chain(path, FALSE)) {
        fwprintf(stderr, L"Refusing the unresolved path %ls.\n", path);
        return PATCH_ERROR;
    }
    if (!spp_path_type(path, FALSE, FALSE)) {
        fwprintf(stderr, L"Not a regular file: %ls.\n", path);
        return PATCH_ERROR;
    }
    wcsncpy(edit->path, path, PATH_SIZE - 1);
    edit->path[PATH_SIZE - 1] = L'\0';
    edit->file = spp_open(edit->path, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
    if (edit->file == INVALID_HANDLE_VALUE) {
        ci_io_error(L"open offline target", edit->path, GetLastError());
        return PATCH_ERROR;
    }
    wchar_t final[OFFLINE_NT_PATH];
    if (!GetFileInformationByHandle(edit->file, &edit->id) || !offline_path_name(edit->file, final)) {
        ci_io_error(L"resolve the identity of", edit->path, GetLastError());
        return PATCH_ERROR;
    }
    if (!offline_under(final, scope->allow_final) || offline_under(final, scope->live_final)) {
        fwprintf(stderr, L"Target resolves outside the selected folder or inside the running Windows installation: %ls.\n",
                 edit->path);
        return PATCH_ERROR;
    }
    if (!ci_check_live_file(edit, scope->live, name, &scope->live_dir))
        return PATCH_ERROR;
    if (!offline_read(edit->file, &edit->before, algorithm)) {
        fwprintf(stderr, L"Cannot read or verify %ls.\n", edit->path);
        return PATCH_ERROR;
    }
    GetFileTime(edit->file, &edit->created, &edit->accessed, &edit->written);

    if (recognized && recognized(edit->path, context)) {
        edit->after.size = edit->before.size;
        edit->after.data = malloc(edit->after.size);
        if (!edit->after.data) {
            fwprintf(stderr, L"Cannot allocate a verification buffer for %ls.\n", edit->path);
            return PATCH_ERROR;
        }
        memcpy(edit->after.data, edit->before.data, edit->after.size);
        memcpy(edit->after.sha, edit->before.sha, sizeof edit->after.sha);
        edit->after.machine = image_machine_hint(edit->before.data, edit->before.size);
        edit->after.changed = FALSE;
        wprintf(L"%ls\n  already carries this package's local signature  SHA-256 %hs\n",
                edit->path, edit->after.sha);
        return PATCH_READY;
    }

    /* An existing retained original is the base for everything this mode writes.
       It keeps the patch set complete when an earlier build applied only part of
       it, and a retry can finish without a manual restore. */
    Output base = {0};
    wchar_t backup_path[PATH_SIZE];
    BOOL have_backup = FALSE;
    if (ci_find_backup(edit->path, backup_path)) {
        HANDLE backup = spp_open(backup_path, GENERIC_READ | READ_CONTROL, OPEN_EXISTING);
        have_backup = backup != INVALID_HANDLE_VALUE && offline_read(backup, &base, algorithm);
        if (backup != INVALID_HANDLE_VALUE)
            CloseHandle(backup);
        if (!have_backup) {
            fwprintf(stderr, L"Cannot read the retained original %ls. No files changed.\n", backup_path);
            return PATCH_ERROR;
        }
        memcpy(edit->base_sha, base.sha, sizeof edit->base_sha);
    }
    const Output *source = have_backup ? &base : &edit->before;
    Image image;
    Plan edits = {0};
    BOOL structured = image_open_arch(&image, source->data, source->size, TRUE) &&
                      plan(&image, &edits) && (edits.count || edits.existing);
    BOOL changed = FALSE;
    if (!structured) {
        free(base.data);
        if (optional_structure) {
            wprintf(L"%ls\n  No supported structure for this mode. File left unchanged.\n", edit->path);
            /* The file is not modified, but it is part of the operation: keep its
               original so a restore covers every target of the command. */
            if (!patch_retain_copy(edit->path))
                wprintf(L"  The original could not be retained next to it.\n");
            else
                wprintf(L"  Original retained as FILE.bak next to the target.\n");
            return PATCH_ABSENT;
        }
        fwprintf(stderr, L"Unsupported or ambiguous structure in %ls. No files changed.\n",
                 have_backup ? backup_path : edit->path);
        return PATCH_ERROR;
    }
    if (!patch_build_after(algorithm, source, &edits, &image, &edit->after, &changed)) {
        fwprintf(stderr, L"Cannot verify the prepared patch for %ls.\n", edit->path);
        free(base.data);
        return PATCH_ERROR;
    }
    if (build) {
        /* The hook may change the image size, so checksum and hash follow it. */
        if (!build(algorithm, &edit->after, context) ||
            !fix_checksum(edit->after.data, edit->after.size) ||
            !digest(algorithm, edit->after.data, edit->after.size, edit->after.sha)) {
            fwprintf(stderr, L"Cannot prepare the post-processing step for %ls. No files changed.\n", edit->path);
            free(base.data);
            return PATCH_ERROR;
        }
    }

    if (have_backup) {
        if (!strcmp(edit->before.sha, base.sha)) {
            /* The retained original is still in place: write the full patch. */
        } else if (!strcmp(edit->before.sha, edit->after.sha)) {
            changed = FALSE; /* already fully patched */
        } else if (!patch_subset_matches(algorithm, &edit->before, &base, &edits)) {
            fwprintf(stderr, L"%ls is neither the retained original nor the result of this patch. "
                             L"Restore it first or move the backup away. No files changed.\n", edit->path);
            free(base.data);
            return PATCH_ERROR;
        }
    }
    free(base.data);

    wprintf(L"%ls\n", edit->path);
    for (unsigned i = 0; i < edits.count; ++i)
        wprintf(L"  %06lX  %ls\n", edits.edits[i].at, edits.edits[i].label);
    edit->after.changed = changed;
    wprintf(L"  %ls  SHA-256 %hs\n", changed ? L"ready" : L"already patched", edit->after.sha);
    return PATCH_READY;
}

/* Back up, lock, write and verify every prepared edit; roll back on any failure.
   Handles are closed after each write so a post hook (signing, for example) can
   reopen the file itself. */
static BOOL patch_edits_commit(BCRYPT_ALG_HANDLE algorithm, OfflineEdit *edits, unsigned count,
                              PatchPost post, void *context)
{
    BOOL ok = TRUE;
    for (unsigned i = 0; ok && i < count; ++i) {
        OfflineEdit *edit = &edits[i];
        if (edit->file == INVALID_HANDLE_VALUE || !edit->after.changed)
            continue;
        if (!ci_original_backup(edit, algorithm) || !offline_lock(edit, algorithm)) {
            fwprintf(stderr, L"Patch preparation failed for %ls. The target contents were not written.\n", edit->path);
            ok = FALSE;
        }
    }
    for (unsigned i = 0; ok && i < count; ++i) {
        OfflineEdit *edit = &edits[i];
        if (edit->file == INVALID_HANDLE_VALUE || !edit->after.changed)
            continue;
        edit->touched = TRUE;
        ok = offline_write(edit, &edit->after, algorithm);
        if (!ok)
            ci_io_error(L"write and verify", edit->path, GetLastError());
        if (edit->file != INVALID_HANDLE_VALUE) {
            CloseHandle(edit->file);
            edit->file = INVALID_HANDLE_VALUE;
        }
    }
    for (unsigned i = 0; ok && post && i < count; ++i) {
        OfflineEdit *edit = &edits[i];
        if (!edit->touched)
            continue;
        ok = post(algorithm, edit, context);
        if (!ok)
            fwprintf(stderr, L"Post-processing failed for %ls.\n", edit->path);
    }
    if (!ok) {
        for (unsigned i = count; i > 0; --i) {
            OfflineEdit *edit = &edits[i - 1];
            if (!edit->touched)
                continue;
            HANDLE file = spp_open(edit->path, GENERIC_READ | GENERIC_WRITE, OPEN_EXISTING);
            if (file == INVALID_HANDLE_VALUE) {
                fwprintf(stderr, L"Rollback failed. Restore the retained backup for %ls.\n", edit->path);
                continue;
            }
            OfflineEdit restore = {.file = file};
            wcsncpy(restore.path, edit->path, PATH_SIZE - 1);
            if (!offline_write(&restore, &edit->before, algorithm))
                fwprintf(stderr, L"Rollback failed. Restore the retained backup for %ls.\n", edit->path);
            CloseHandle(file);
        }
    }

    BOOL metadata_ok = TRUE;
    for (unsigned i = count; i > 0; --i) {
        OfflineEdit *edit = &edits[i - 1];
        if (edit->touched && !patch_keep_times(edit->path, &edit->created, &edit->accessed, &edit->written))
            metadata_ok = ci_io_error(L"restore the timestamps of", edit->path, GetLastError());
        if (edit->restore_readonly) {
            HANDLE attributes = spp_open(edit->path, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, OPEN_EXISTING);
            BOOL restored = attributes != INVALID_HANDLE_VALUE && offline_readonly(attributes, TRUE);
            DWORD error = GetLastError();
            if (attributes != INVALID_HANDLE_VALUE)
                CloseHandle(attributes);
            if (!restored)
                metadata_ok = ci_io_error(L"restore the read-only attribute of", edit->path, error);
        }
        patch_edit_release(edit);
    }
    return ok && metadata_ok;
}

/* Classify a command argument: a single file, a flat folder of extracted files,
   or an offline Windows root that contains Windows. */
typedef enum { INPUT_FILE, INPUT_FLAT, INPUT_ROOT } InputKind;static BOOL patch_input_kind(const wchar_t *path, InputKind *kind)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return FALSE;
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        *kind = INPUT_FILE;
        return TRUE;
    }
    wchar_t windows[PATH_SIZE], system32[PATH_SIZE];
    if (swprintf(windows, PATH_SIZE, L"%ls\\Windows", path) < 0 ||
        swprintf(system32, PATH_SIZE, L"%ls\\System32", windows) < 0)
        return FALSE;
    DWORD windows_attributes = GetFileAttributesW(windows);
    DWORD system32_attributes = GetFileAttributesW(system32);
    *kind = windows_attributes != INVALID_FILE_ATTRIBUTES &&
                    (windows_attributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    system32_attributes != INVALID_FILE_ATTRIBUTES &&
                    (system32_attributes & FILE_ATTRIBUTE_DIRECTORY) ? INPUT_ROOT : INPUT_FLAT;
    return TRUE;
}

static BOOL patch_parent_directory(const wchar_t *path, wchar_t parent[PATH_SIZE])
{
    size_t length = wcslen(path);
    if (length < 4 || length >= PATH_SIZE)
        return FALSE;
    size_t i = length;
    while (i > 0 && path[i - 1] != L'\\')
        --i;
    if (!i || i > length)
        return FALSE;
    size_t keep = i - 1;
    if (keep < 3)
        keep = 3;
    memcpy(parent, path, keep * sizeof *path);
    parent[keep] = L'\0';
    return TRUE;
}

static const wchar_t *patch_leaf(const wchar_t *path)
{
    const wchar_t *leaf = wcsrchr(path, L'\\');
    return leaf ? leaf + 1 : path;
}


/* One file of a multi-file patch operation. */
typedef struct {
    const wchar_t *relative;   /* path below the base folder, or NULL for a full path */
    const wchar_t *name;       /* leaf name, used for messages and the live alias check */
    BOOL required;             /* an absent file stops the operation */
    BOOL skip_unsupported;     /* an unrecognized structure is reported and skipped */
    PatchPlan plan;
    PatchBuild build;
    PatchRecognized recognized;
} PatchSpec;

enum { SPEC_MISSING = 0, SPEC_CHANGED = 1, SPEC_ALREADY = 2 };

/* Prepare every spec, then commit them together. states receives one of the
   SPEC_* values per spec. */
static BOOL patch_specs(BCRYPT_ALG_HANDLE algorithm, const PatchScope *scope, const wchar_t *base,
                        const PatchSpec *specs, unsigned count, unsigned char *states,
                        PatchPost post, void *context)
{
    OfflineEdit *edits = calloc(count, sizeof *edits);
    BY_HANDLE_FILE_INFORMATION *ids = calloc(count, sizeof *ids);
    if (!edits || !ids) {
        fwprintf(stderr, L"Cannot allocate patch state for %u files.\n", count);
        free(edits);
        free(ids);
        return FALSE;
    }
    BOOL ok = TRUE;
    for (unsigned i = 0; i < count; ++i) {
        wchar_t path[PATH_SIZE];
        if (base) {
            if (!build_path(path, base, specs[i].relative)) {
                fwprintf(stderr, L"Path too long: %ls\\%ls\n", base, specs[i].relative);
                ok = FALSE;
                break;
            }
        } else if (wcslen(specs[i].relative) >= PATH_SIZE) {
            ok = FALSE;
            break;
        } else {
            wcsncpy(path, specs[i].relative, PATH_SIZE - 1);
            path[PATH_SIZE - 1] = L'\0';
        }
        int result = patch_edit_prepare(algorithm, scope, path, specs[i].name, specs[i].required,
                                        specs[i].skip_unsupported, specs[i].plan, specs[i].build,
                                        specs[i].recognized, context, &edits[i]);
        if (result == PATCH_ERROR) {
            ok = FALSE;
            break;
        }
        if (result == PATCH_ABSENT) {
            states[i] = SPEC_MISSING;
            patch_edit_release(&edits[i]);
            continue;
        }
        /* Hard-linked System32\Boot copies are the same file object. Patch once. */
        BOOL duplicate = FALSE;
        for (unsigned j = 0; j < i; ++j) {
            if (states[j] == SPEC_MISSING || !offline_file_id(&ids[j], &edits[i].id))
                continue;
            if (specs[j].plan != specs[i].plan) {
                fwprintf(stderr, L"Conflicting patch roles for linked file %ls.\n", edits[i].path);
                ok = FALSE;
            }
            states[i] = states[j];
            patch_edit_release(&edits[i]);
            duplicate = TRUE;
            break;
        }
        if (!ok)
            break;
        if (duplicate)
            continue;
        ids[i] = edits[i].id;
        states[i] = edits[i].after.changed ? SPEC_CHANGED : SPEC_ALREADY;
    }
    if (ok)
        ok = patch_edits_commit(algorithm, edits, count, post, context);
    else
        for (unsigned i = 0; i < count; ++i)
            patch_edit_release(&edits[i]);
    free(ids);
    free(edits);
    return ok;
}

/* Report one summary line per spec, using only the states already collected. */
static void patch_report(const wchar_t *base, const unsigned char *states, unsigned count)
{
    unsigned changed = 0, already = 0;
    for (unsigned i = 0; i < count; ++i) {
        changed += states[i] == SPEC_CHANGED;
        already += states[i] == SPEC_ALREADY;
    }
    if (changed)
        wprintf(L"%u file(s) patched in %ls.\n", changed, base ? base : L"the selected location");
    else if (already)
        wprintf(L"All %u recognized file(s) already carry this patch in %ls.\n", already,
                base ? base : L"the selected location");
    else
        wprintf(L"No files were changed.\n");
}




