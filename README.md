# NT Timebomb Patch 6.0.0

Offline servicing for FlightSigned Windows previews: the CI build expiry, the signed
boot chain of a WinPE/ISO medium, the licensing side, and the media build itself.
**Every match is done on byte structure — never on a build number and never on a fixed
offset.** When a layout is not recognised the file is left untouched and the tool says
so instead of guessing.

Chinese documentation: [README.zh-CN.md](README.zh-CN.md).
WinPE boot chain details: [WINPE.md](WINPE.md). 32-bit CI details: [X86-CI.md](X86-CI.md).

Run `nttimebomb.cmd /version` for the version, `/help` for the built-in summary.

---

## 1. Requirements

- **Elevation**: offline servicing needs an elevated prompt. In WinPE use a SYSTEM
  prompt (`NSudoLC.exe -U:S -P:E cmd.exe` or the WinPE SYSTEM shell).
- **Local drive paths** under `MAX_PATH`; quote paths containing spaces.
- **Secure Boot off**: every patched boot file loses its Authenticode signature by
  design, so the firmware must not verify it.
- `/media` needs `oscdimg.exe` and (for ISO input) `7z.exe`; pass them with
  `/oscdimg` and `/7zip`, place them beside the executable, or have them in `PATH`.

---

## 2. The three entry points

```bat
:: 1. An offline Windows image (install.wim mounted or extracted)
nttimebomb /image D:\mount
nttimebomb /image D:\install.wim /out D:\install-patched.wim

:: 2. A WinPE / installation medium (the extracted ISO tree)
nttimebomb /winpe D:\media
nttimebomb /winpe D:\media /bootmgr-from D:\verified-media   :: replace boot managers

:: 3. A boot.wim, patched in place or copied
nttimebomb /bootwim D:\boot.wim /out D:\boot-patched.wim
```

`/image` and `/bootwim` share the same **loader recipe**; `/winpe` additionally patches
the medium's boot managers and the copies embedded in the El Torito image, and writes
`nointegritychecks on` into every BCD store it finds. `/winpe` replaces files **in
place and keeps no `.bak` copies**; `/image` and `/bootwim` keep the original next to
the target.

---

## 3. How the matching works

Three independent chains, each of which requires a **unique structural hit**. A chain
that does not match hands over to the next one; the last resort either patches with the
generic gates or leaves the file alone.

### 3.1 `ci.dll` (the build-expiry check)

1. **Four-branch recipe** (10074 / 10120 / 10166 x64): four `jcc → EB` branches, byte
   identical to a working reference.
2. **Late recipe** (10587 / 14300 / 14372):
   - the unique `a8 01 74 17` expiry gate → `90 90`,
   - two `test cl, cl ; je` branches guarded by the flighting bits → `EB`.
3. **Producer walk** (14951 and close builds): for every `mov reg, 0C0000605h` producer,
   walk back to the nearest `test cl, cl ; je` and turn the `je` into an unconditional
   skip.
4. **Classic planner**: the historical generic rule, plus `plan_umci`.

### 3.2 Loaders (`winload` / `winresume`, `.efi` and `.exe`)

1. **Reference recipe** (10074 generation, byte identical to a working image):
   - `mov ebx, eax` after the hash call → `xor eax, eax`,
   - `mov [rsp+40h], cl` (integrity switch) → `mov cl, 1`,
   - `mov edi, eax` before the alternate-status check → `xor eax, eax`.
2. **Structural gates**: image hash gate, catalog/alternate status, parsed revocation
   list (`0C0000603h`), file revocation result, loader integrity option.

### 3.3 Medium boot managers (`bootmgr.efi`, `bootx64.efi`, `memtest.efi`, `cdboot`)

1. **Verified four-edit set** (14316 / 14349 / 14357), byte identical to a known-good
   medium;
2. **9841 generation** (two status clears + one status gate; x86 and x64 variants);
3. **Reference media recipe** (10074 / 10120 / 10166 / 10587): the integrity switch is
   located first (`0f b6 4c 24 40 85 c0 41 0f 48 ce`), then every status check within
   one function-sized window around it is grouped by its call target and cleared
   (`mov ebx, eax → xor eax, eax`); the store becomes `mov cl, 1`;
4. **Generic gates**: image hash status, boot application status, catalog status,
   parsed revocation list.

---

## 4. Verified builds

| Build | `/image` | `/winpe` |
| --- | --- | --- |
| 9841 x64 | verified (boots) | verified (boots) |
| 9841 x86 | verified, byte identical to a working pair | verified |
| 9926 x86 | structural (status clears before the flag test) | structural |
| 10074 x64 | **byte identical** to a working `install.wim` (`ci.dll`, `winload.efi`, `winresume.efi`, checksums included) | **code byte identical** to a working medium (`bootmgr.efi`, `memtest.efi`); UEFI and Legacy boot tested |
| 10074 x86 | 9841-generation rules | 9841-generation rules |
| 10120 x64 | four-branch CI + reference loaders | reference media recipe |
| 10166 x64 | four-branch CI + reference loaders | reference media recipe |
| 10587 x64 | late CI recipe (sites match the old patched set) | reference media recipe |
| 14300 x64 | late CI recipe, `ci.dll` **byte identical** to the old patched set | reference media recipe |
| 14372 x64 | late CI recipe | boot managers matched, BIOS `bootmgr` untouched |
| 14951 x64 | producer-walk CI + reference loaders | boot managers matched, BIOS `bootmgr` untouched |

"Byte identical" means the resulting file equals a known-bootable reference including
the PE checksum; the only differences that remain are the reference's re-signed
certificate blob, which cannot and need not be reproduced.

### Known limits

- **14951 BIOS `bootmgr`** (the 16/32-bit container): the generic legacy rebuild cannot
  match it uniquely, so it is left untouched and the tool prints
  `Could not uniquely match the image hash caller`.
- **14372 / 14951 media**: the boot managers get the reference media recipe, but no
  boot-tested reference exists for those builds yet.
- Builds whose `ci.dll` predates the four-branch layout and lacks both late signatures
  fall back to the classic planner; if that fails the file is left untouched.

---

## 5. `/winpe` in detail

```bat
nttimebomb /winpe D:\media
```

- Patches `bootmgr.efi`, `efi\boot\bootx64.efi` (or `bootia32.efi`), `bootmgr`,
  `boot\memtest.exe`, `efi\microsoft\boot\memtest.efi`, `cdboot*.efi`, and the copies
  embedded in `efisys*.bin` (in place, container size unchanged);
- Writes `nointegritychecks on` into `EFI\Microsoft\Boot\BCD` and `boot\bcd` where they
  exist (needs elevation; otherwise prints the exact `bcdedit` command);
- **Keeps no `.bak` copies** — files are replaced in place;
- `boot.wim` is not modified; use `/bootwim` for that.

Pack the result with `oscdimg -bootdata` so the patched El Torito image is used, e.g.

```bat
oscdimg -m -o -h -u1 -udfver102 -j ^
  -bootdata:2#p0,e,bD:\media\boot\etfsboot.com#pEF,e,bD:\media\efi\microsoft\boot\efisys.bin ^
  D:\media D:\out.iso
```

`/bootmgr-from VERIFIED_MEDIA_ROOT` copies `bootmgr.efi` and `efi\boot\bootx64.efi`
from a known-good medium instead of patching them — useful when a build's boot managers
are not recognised.

---

## 6. Other commands

| Command | Purpose |
| --- | --- |
| `/cishim`, `/cishim-boot` (+ `-restore`) | CI + loader servicing for an offline root with BCD handling |
| `/slshim` | licensing side of the preview (SPP) |
| `/nt6` | legacy NT6 boot path |
| `/bcd ESP_OR_MEDIA_ROOT` | show/write `nointegritychecks` for both BCD stores |
| `/bcd-template` | create a minimal BCD store |
| `/restore` | put the retained originals back |
| `/bootfiles INPUT /out DIR` | patch a loose folder of boot files |
| `/media ISO_OR_DIR` | patch an ISO or a media tree end to end |
| `/enable-lua`, `/disable-lua` | toggle the Lua/PPL side |
| `/version`, `/help` | version and summary |

---

## 7. Safety model

- Every edit is bound to a unique structural pattern; a non-unique match aborts that
  file instead of writing a guess.
- Plans are re-verified after writing (hash of the produced file), and the PE checksum
  is recomputed over the whole file.
- Unrecognised layouts are reported (`Unsupported or ambiguous structure`,
  `layout not recognised`) and left byte-identical to the input.
- The generated output for the verified builds above equals the working reference
  byte for byte, so a regression shows up as a non-zero diff immediately.
