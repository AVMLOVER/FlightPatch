/* /winload-modify - service the boot loaders that firmware starts.

   A release Windows installation keeps its own loader on the EFI System
   Partition (EFI\Microsoft\Boot\winload.efi) or in its Windows folder for a
   legacy (BIOS) start. Those loaders apply the same expired-image gates as the
   preview loaders, so they refuse an OS whose CI and kernel were modified.
   This mode patches the supplied volume's loaders with the same structural
   rules as /cishim-boot, and optionally the legacy boot manager and loaders of
   a second volume that holds a BIOS-boot installation. */

static BOOL plan_boot_manager(const Image *im, Plan *plan)
{
    return plan_boot(im, plan, FALSE);
}

typedef struct {
    const wchar_t *relative;
    const wchar_t *name;
    BOOL required;
    BOOL skip_unsupported;
    PatchPlan plan;
} LoaderTarget;

static const LoaderTarget efi_loaders[] = {
    {L"EFI\\Microsoft\\Boot\\winload.efi", L"winload.efi", TRUE, FALSE, plan_loader_gates},
    {L"EFI\\Microsoft\\Boot\\winresume.efi", L"winresume.efi", FALSE, TRUE, plan_loader_gates}
};

static const LoaderTarget legacy_loaders[] = {
    {L"bootmgr", L"bootmgr", FALSE, TRUE, plan_boot_manager},
    {L"Boot\\winload.exe", L"winload.exe", FALSE, TRUE, plan_loader_gates},
    {L"Boot\\winresume.exe", L"winresume.exe", FALSE, TRUE, plan_loader_gates},
    {L"Windows\\System32\\winload.exe", L"winload.exe", FALSE, TRUE, plan_loader_gates},
    {L"Windows\\System32\\winresume.exe", L"winresume.exe", FALSE, TRUE, plan_loader_gates}
};

enum {
    EFI_LOADER_COUNT = sizeof efi_loaders / sizeof efi_loaders[0],
    LEGACY_LOADER_COUNT = sizeof legacy_loaders / sizeof legacy_loaders[0]
};

static BOOL winload_present(const wchar_t *base, const LoaderTarget *targets, unsigned count,
                            const wchar_t *name)
{
    wchar_t path[PATH_SIZE];
    for (unsigned i = 0; i < count; ++i)
        if (!_wcsicmp(targets[i].name, name) && build_path(path, base, targets[i].relative) &&
            GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES)
            return TRUE;
    return FALSE;
}

static BOOL patch_loader_volume(BCRYPT_ALG_HANDLE algorithm, const wchar_t *base,
                                const LoaderTarget *targets, unsigned count, BOOL efi)
{
    PatchScope scope;
    if (!patch_scope_init(&scope, base)) {
        fwprintf(stderr, L"Cannot resolve a safe folder at %ls.\n", base);
        return FALSE;
    }
    PatchSpec specs[EFI_LOADER_COUNT > LEGACY_LOADER_COUNT ? EFI_LOADER_COUNT : LEGACY_LOADER_COUNT];
    unsigned char states[EFI_LOADER_COUNT > LEGACY_LOADER_COUNT ? EFI_LOADER_COUNT : LEGACY_LOADER_COUNT] = {0};
    for (unsigned i = 0; i < count; ++i)
        specs[i] = (PatchSpec){.relative = targets[i].relative, .name = targets[i].name,
                               .required = targets[i].required && !efi,
                               .skip_unsupported = targets[i].skip_unsupported,
                               .plan = targets[i].plan};
    if (!patch_specs(algorithm, &scope, base, specs, count, states, NULL, NULL))
        return FALSE;
    unsigned changed = 0, already = 0;
    for (unsigned i = 0; i < count; ++i) {
        changed += states[i] == SPEC_CHANGED;
        already += states[i] == SPEC_ALREADY;
    }
    if (!changed && !already) {
        fwprintf(stderr, L"No supported loader was found under %ls.\n", base);
        return FALSE;
    }
    patch_report(base, states, count);
    return TRUE;
}

static BOOL patch_winload_modify(BCRYPT_ALG_HANDLE algorithm, const wchar_t *efi_volume,
                                 const wchar_t *legacy_volume)
{
    if (!winload_present(efi_volume, efi_loaders, EFI_LOADER_COUNT, L"winload.efi") &&
        !winload_present(efi_volume, efi_loaders, EFI_LOADER_COUNT, L"winresume.efi")) {
        fwprintf(stderr, L"No EFI\\Microsoft\\Boot\\winload.efi on %ls. Point the switch at the EFI System Partition.\n",
                 efi_volume);
        return FALSE;
    }
    if (!patch_loader_volume(algorithm, efi_volume, efi_loaders, EFI_LOADER_COUNT, TRUE))
        return FALSE;
    if (!legacy_volume)
        return TRUE;
    if (winload_present(legacy_volume, legacy_loaders, LEGACY_LOADER_COUNT, L"winload.exe"))
        return patch_loader_volume(algorithm, legacy_volume, legacy_loaders, LEGACY_LOADER_COUNT, FALSE);
    wprintf(L"No legacy loader under %ls. Only the EFI loaders were serviced.\n", legacy_volume);
    return TRUE;
}



