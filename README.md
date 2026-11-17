# NT Timebomb Patch 5.4.2

Offline servicing for FlightSigned Windows previews: the CI build expiry, the signed
boot chain of a WinPE medium, the licensing side, and the media build itself. All
matching is done on **byte structure**, never on a build number or a fixed offset.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md).
WinPE boot chain details: [WINPE.md](WINPE.md). 32-bit CI details: [X86-CI.md](X86-CI.md).

Run `nttimebomb.cmd /version` to print the version, `/help` for the built-in summary.

---

## 1. Requirements

- **Elevation**: offline servicing needs an elevated prompt. In WinPE use a SYSTEM
  prompt (`NSudoLC.exe -U:S -P:E cmd.exe` or the WinPE SYSTEM shell).
- **Local drive paths** under `MAX_PATH`; quote paths that contain spaces.
- **Secure Boot off**: every patched boot file loses its Authenticode signature by
  design (the reference patches do the same), so firmware must not verify it.
- For `/cishim` on a preview: the target boot entry needs `nointegritychecks on`,
  otherwise the loader rejects the patched `ci.dll` with `0xc0000428`.
- `/media` needs `oscdimg.exe` and (for ISO input) `7z.exe`; pass them with
  `/oscdimg` and `/7zip`, place them beside the executable, or have them in `PATH`.

---

## 2. Preview CI build expiry (`/cishim`)

```bat
:: ci.dll plus the complete loader set, then set the BCD options
nttimebomb.cmd /cishim D:\mount /bcd S:\
:: only the loaders
nttimebomb.cmd /cishim-boot D:\mount
:: undo
nttimebomb.cmd /cishim-restore D:\mount
nttimebomb.cmd /cishim-boot-restore D:\mount
```

- Processes `System32\ci.dll` and `winload.efi`, `winresume.efi`, `winload.exe`,
  `winresume.exe` plus their `System32\Boot` copies.
- Accepts an offline Windows root, an extracted folder, or a single file.
- The loader part keeps only the explicit BCD `nointegritychecks` option; the image
  hash / catalog / revocation gates belong to `/winload-modify`.
- A missing or unsupported loader stops the run before `ci.dll` is written.
- Unknown or ambiguous structures fail without writing anything.
- Every changed file keeps a `FILE.bak` next to it (owner, DACL, timestamps).

## 3. Boot chain of an expired WinPE (`/winpe`)

Flightsigned PE media stops booting once the certificates expire: the boot manager
(and the CD boot application) refuse the loader inside `boot.wim`. `/winpe` patches
the **boot chain only** and leaves `boot.wim` untouched.

```bat
:: 1. patch the PE image itself
nttimebomb.cmd /bootwim D:\media\sources\boot.wim
:: 2. patch the boot chain of the extracted medium
nttimebomb.cmd /winpe D:\media
:: 3. build the ISO - oscdimg is REQUIRED, see the warning below
oscdimg -m -o -h -u1 -udfver102 -j ^
  -bootdata:2#p0,e,bD:\media\boot\etfsboot.com#pEF,e,bD:\media\efi\microsoft\boot\efisys.bin ^
  D:\media D:\out.iso
```

What `/winpe` touches:

| File | Rule |
| --- | --- |
| `bootmgr.efi`, `efi\boot\bootx64.efi`, `efi\microsoft\boot\bootmgfw.efi` | 4 surgical edits (image status gate, its `js` form, catalog gate, revocation result) |
| `efi\boot\bootia32.efi` | 1 edit (32-bit status gate) |
| `cdboot.efi`, `cdboot_noprompt.efi` | 2 edits (`jns` to `jmp`) |
| `efi\microsoft\boot\efisys.bin`, `efisys_noprompt.bin` | the embedded `BOOTX64.EFI` is patched in place, container size unchanged |
| `memtest.efi`, `boot\memtest.exe` | patched when the layout matches, skipped otherwise |
| `bootmgr` (BIOS) | unpacked, patched and rebuilt; **experimental** |

**Packaging warning**: the UEFI boot image is a copy stored in the ISO itself, not
the file in the directory tree. UltraISO and similar tools keep the source ISO's
boot image, so replacing `efi\microsoft\boot\efisys.bin` in the tree has no effect.
Use `oscdimg` with `-bootdata` so the patched `efisys.bin` becomes the boot image.
This is verified: the patched `cdboot.efi` and the copy inside `efisys.bin` are
byte for byte identical to a known-good medium, checksum included.

**VMware + Legacy (99xx-series builds only)**: the guest may panic in the VM monitor
(`hypervMonitor_syn.c:940`). Later and earlier builds are not affected. The tool no longer writes a BCD workaround, because it
does not help. Remove the `vhv.enable` and `hypervisor.cpuid.v0` lines from the
`.vmx` (or clear "Virtualize Intel VT-x/EPT or AMD-V/RVI").

## 4. Complete installation media (`/media`)

```bat
nttimebomb.cmd /media D:\Preview.iso /work D:\NTTP-Work /out D:\Preview-patched.iso ^
           /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe /winpe
```

- Extracts or copies the source into `WORK`, services every `boot.wim` and
  `install.wim` index, then rebuilds a BIOS + UEFI ISO with `oscdimg`.
- `/winpe` additionally patches the boot chain **inside the work folder**, including
  the copy embedded in `efisys*.bin`; the rebuilt ISO uses the patched file as its
  UEFI boot image (`-bootdata`).
- `sources\boot.wim` is patched like `/bootwim` in every mode **except** `/spponly`
  and `/nt6`. `/bootwim` is accepted as a no-op flag for compatibility.
- `WORK` must not exist yet; it stays available for inspection after any result.

```bat
:: SPP only (install.wim indexes)
nttimebomb.cmd /media SRC.iso /work W /out O.iso /spponly D:\RTM
:: NT6 tokens + optional Branding (install.wim indexes)
nttimebomb.cmd /media SRC.iso /work W /out O.iso /nt6 D:\DONOR
```

`/media` requires standalone `sources\boot.wim` and `sources\install.wim` plus the
BIOS/UEFI El Torito files. Split WIMs and `install.esd` are not accepted.

## 5. Preview images below Build 15063

```bat
nttimebomb.cmd /image D:\mount [/boot S:] [/recovery D:\Recovery] [/spp D:\RTM]
nttimebomb.cmd /spponly D:\mount /spp D:\RTM
nttimebomb.cmd /spponly IN.wim /out OUT.wim /spp D:\RTM [/index N|all]
nttimebomb.cmd /bootwim D:\mount
nttimebomb.cmd /bootwim IN.wim /out OUT.wim [/index N]
```

- `/image` services CI, loaders, kernel expiry and (with `/spp`) SPP on an offline root.
- `/spponly` replaces SPP, preserving boot files, CI, kernels and LicensingUI; a donor
  is required (`spp*` shared files and the SKU `*.cat` files side by side, an optional
  `CatRoot` subfolder).
- `/nt6 /file DONOR /target ROOT` copies only `System32\spp\tokens` (plus optional
  `Branding`), grants `NT SERVICE\sppsvc` full control, and refuses Build 15063+.
- **Build 15063 and newer is refused**: nothing is changed, the message points at
  `/cishim` (CI) and `/slshim` (licensing).
- `/index all` services every index; `/image` and `/spponly` default to index 1,
  `/bootwim` defaults to all.

## 6. Boot configuration (`/bcd`, `/bcd-template`)

```bat
nttimebomb.cmd /bcd S:\                 :: ESP: EFI\Microsoft\Boot\BCD
nttimebomb.cmd /bcd D:\media            :: media root: both EFI and boot\bcd
nttimebomb.cmd /bcd S:\ {GUID}
nttimebomb.cmd /bcd-show D:\media
nttimebomb.cmd /bcd-template D:\mount   :: Windows\System32\config\BCD-Template
```

`/bcd` writes `nointegritychecks on` (required by the patched `ci.dll`) and
`recoveryenabled No` (so a failed start stops at the boot menu instead of running
automatic repair). `/bcd-template` prepares an image so newly created stores inherit
both settings. `/cishim` and `/cishim-boot` accept `/bcd ESP` to do it in one step.

## 7. LUA switch (`/enable-lua`, `/disable-lua`)

```bat
nttimebomb.cmd /disable-lua            :: running system (elevated), EnableLUA = 0
nttimebomb.cmd /disable-lua W:\        :: offline volume's config\SOFTWARE hive
nttimebomb.cmd /enable-lua
```

Writes `EnableLUA` (0 or 1) in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`.
The offline path reuses the certificate-store machinery (previous hive kept as a
backup). A restart is required. The three uiAccess programs (`osk.exe`,
`Narrator.exe`, `Magnify.exe`) only start with `EnableLUA=0`; four alternative
repairs were measured ineffective.

## 8. Licensing shim (`/slshim`, experimental)

```bat
nttimebomb.cmd /slshim D:\mount
nttimebomb.cmd /slshim-restore D:\mount
```

Replaces the licensing client DLLs, disables existing Windows licensing services and
installs a LocalSystem shim using that SKU's ProductPolicy. Backups live in
`OFFLINE_ROOT\NTTimebombBackup\SLShim`. This is a local licensing emulation, not a
Microsoft licence or online activation. Never implied by `/image`, `/spp`, `/nt6`,
`/media` or `/cishim`; it does not touch CI, boot files or LicensingUI.

## 9. Restore

```bat
nttimebomb.cmd /restore D:\mount
nttimebomb.cmd /cishim-restore D:\mount
nttimebomb.cmd /cishim-boot-restore D:\mount
nttimebomb.cmd /winload-modify-restore D:\mount
```

Every changed file keeps a verified `FILE.bak` (original owner, DACL, attributes);
older packages used `FILE.nttp-original`, also accepted. Restore writes the original
bytes back, re-applies the metadata, verifies the result and removes that backup.
Files without a retained original are left alone. Use `/cishim-restore` from WinPE
to undo a `/cishim` that does not boot.

## 10. Command surface

| Command | Purpose |
| --- | --- |
| `/cishim`, `/cishim-boot` (+ `/bcd ESP`) | preview CI build expiry and loader set |
| `/winload-modify` | loader image-hash / catalog / revocation / integrity-option gates |
| `/winpe PE_ROOT` | boot chain of an expired WinPE medium |
| `/bootwim` | patch a `boot.wim` (CI, loaders, kernel) |
| `/media ...` (+ `/winpe`) | full ISO build: extract, service, rebuild |
| `/image`, `/spponly`, `/spp`, `/spp-reference`, `/nt6` | preview images below 15063 |
| `/bcd`, `/bcd-show`, `/bcd-template` | offline BCD options |
| `/enable-lua`, `/disable-lua` | `EnableLUA` on a running system or an offline hive |
| `/slshim`, `/slshim-restore` | licensing shim (experimental) |
| `/restore`, `*-restore` | write the retained originals back |
| `/bootfiles IN /out OUT` | patch `bootmgr` + `bootmgr.efi` as a pair |
| `/version`, `/help` | version and usage |

Removed from the command surface (implementations are still in the tree):
`/mmc`, `/mmc-restore`, `/mmc-approval`, `/mmc-approval-restore`, `/bootmgr`,
`/wintrust*`, `/uac*`, `/uiaccess*`, `/wd`.

## 11. Building

Zig is enough (`zig cc`, no MSVC needed):

```bat
zig rc /fo as-invoker.res -- src/flightpatch.rc
zig cc -target x86-windows-gnu      -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-x86.exe
zig cc -target x86_64-windows-gnu   -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-x64.exe
zig cc -target aarch64-windows-gnu  -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-arm64.exe
:: the MMC helper (retired from the CLI, code kept)
zig cc -target x86_64-windows-gnu   -municode -std=c11 -Oz -s src/mmc.c as-invoker.res -ladvapi32 -lbcrypt -lwintrust -lcrypt32 -lncrypt -o nttimebomb-mmc-x64.exe
```

`tools/package.py OUTPUT.zip` builds the release archive (binaries, scripts, sources,
dependencies, notices, docs).

## 12. Limitations

- Secure Boot must be off for every patched boot file.
- The BIOS `bootmgr` container rebuild is experimental: verify a Legacy start in a
  virtual machine before writing real media.
- VMware guests may panic in the monitor on Legacy starts of **99xx-series** builds
  only; fix the VM settings, not the media (see section 3).
- **9841 UEFI**: its boot manager layout is older than the verified set, so the
  generic gates do not let the loader through and UEFI stops at `0xc0000428`
  (Legacy is fine). One step:
  `nttimebomb /winpe D:\boot /bootmgr-from D:\Patched_14357.1000_WinPE` copies the
  verified `bootmgr.efi` + `efi\boot\bootx64.efi` over the 9841 ones (originals keep a
  `FILE.bak`); keep 9841's `cdboot*.efi`, `efisys*.bin` and the `/bootwim` result, then
  rebuild with oscdimg.
- 32-bit preview `ci.dll` layouts are covered for 9841, 9860, 9926, 10074, 10143,
  10525, 10546, 10587 and 14347; other layouts are refused rather than guessed.
- Windows Defender on preview builds is out of scope.

Licence: see [LICENSE](LICENSE).
