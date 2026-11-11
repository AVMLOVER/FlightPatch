# 5.3.0 validation

Offline verification used the x64 Windows 10 build 21390 System32 files of a
mounted image: `ci.dll`, `winload.efi`, `winresume.efi`, `winload.exe`,
`winresume.exe`, `wintrust.dll`, `crypt32.dll`, plus the SysWOW64
`wintrust.dll` and `crypt32.dll`. Each mode was checked on a copy; the mounted
image was not modified.

## Boot failures seen on target installations

Two target installations were serviced and both stopped before the desktop.

| Target | Applied | Result |
| --- | --- | --- |
| 21390 x64 | `/cishim` + `/wintrust` | green screen `0xc000021a`, WinRE automatic repair |
| 18247 x64 | `/wintrust` only (CI and loader were patched by 5.3.0 earlier) | green screen `0xc000021a` |

The 21390 recovery log (`Windows\System32\Logfiles\Srt\SrtTrail.txt`) records
`0xc000021a` with second parameter `0xc0000428` and reports a corrupt boot-critical
file. 18247 had been booting with the earlier CI and loader patch, so the change
that appeared with both failures is the rewritten `wintrust.dll`/`crypt32.dll`
pair, not the CI or loader rules. `STATUS_INVALID_IMAGE_HASH` there is produced by
image validation of the rewritten signed DLLs.

Consequences for the rules and for testing:

- `/cishim` and `/cishim-boot` now apply only the integrity-option family to a
  loader (keep the BCD option, force the loader's own option). The image-hash,
  catalog and revocation gate patch moved back to `/winload-modify`, where a
  release loader has to accept a modified image.
- `/wintrust` prints the risk before and after the write, and `/wintrust-restore`
  is the documented WinPE recovery.
- The semantic-neutral `echo` probe in README distinguishes "any edit to this DLL
  is rejected" from "this patch crashes".
- The restore aliases now select a set: `/cishim-restore` clears CI and loaders,
  `/wintrust-restore` clears the certificate modules, `/restore` clears all.

## Round 10: the three uiAccess programs are a LUA problem

The failure of `osk.exe`, `Narrator.exe` and `Magnify.exe` is not the expired
signature, not `consent.exe` and not AppInfo's auto-approval table. Measured on
21390:

| Change | Result |
| --- | --- |
| wintrust/crypt32 patched, four modules signed and trusted | programs still fail |
| `uiAccess="true"` removed from the manifests and signed | programs still fail |
| `consent.exe` AMSI results forced to zero, signed, trusted | programs still fail |
| three programs added to AppInfo's auto-approval table | programs still fail |
| `EnableLUA=0` (the LUA subsystem itself), reboot | **all three start** |

The error is a plain dialog with `ERROR_DS_REFERRAL` (8235), not a UAC prompt, and
it appears only while `EnableLUA=1`. With LUA disabled no filtered token, no consent
and no uiAccess token request exist, so the failing path in `CreateProcess` is never
entered. Lowering the UAC slider does not help because the LUA subsystem stays on.

Consequence for this package: none of the certificate, consent or AppInfo work is
needed for these three programs. `EnableLUA=0` is a user decision with its own
costs (no UAC prompts at all, and Store/UWP applications stop starting), so it is
not automated here.

## Round 9: build-generic certificate matchers

The certificate rules no longer depend on the exact shapes seen on 21390:

- crypt32 exports are still the anchors, but the chain-policy branch is now found
  from the `CERT_E_EXPIRED` constant plus the jump that skips its assignment,
  accepting `mov reg, imm32` and `mov [mem], imm32` with disp8 or disp32.
- wintrust status bits are found by scanning 32 bytes after the call site for
  `test reg,reg` + short jump + any bit-set encoding (`bts`, `or dword`, `or byte`),
  so register allocation and NOP padding no longer matter, and the already patched
  `nop nop` form is recognized.

Checked against the mounted 21390 files:

| File | Result |
| --- | --- |
| System32\wintrust.dll (x64) | 0x25832, 0x2584E — identical to the hand-matched offsets |
| System32\crypt32.dll (x64) | 0x179C0, 0x8C7D0, 0xD2586 — identical |
| SysWOW64\wintrust.dll (x86) | 0x2928B, 0x292A1 |
| SysWOW64\crypt32.dll (x86) | 0x21180, 0x75A50, **0xAF64D** — the policy branch that the previous matcher missed |

Pre-patching the two status-bit branches to `90 90` makes the run report "already
patched", and pre-patching the policy byte to `EB` is recognized as existing.

## Round 8: only one of four queued replacements happened

After the live run reported success and the machine restarted, `/wintrust-status`
showed only `System32\crypt32.dll` replaced (`signed here: yes`, `0x0`, signer
"NT Timebomb Patch local wintrust"); `System32\wintrust.dll` and both SysWOW64
modules were still stock (`0x800B0101`, signer "Microsoft Windows"), and the
journal listed all four entries.

Cause: the scheduling used `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING |
MOVEFILE_DELAY_UNTIL_REBOOT)`. Microsoft documents those two flags as not
combinable, and in practice only one of the four queued operations was applied.
Both the apply and the restore path now queue two documented operations per file:
delete the target at boot, then rename the staged file onto it. The receipt also
keeps the full hex SHA-256 strings instead of truncating them to 32 bytes.

## Round 7: the live run never applied anything

The target's `/wintrust-status` after `/wintrust-approval C:\` and a restart showed
`signed here: no` and `WinVerifyTrust 0x800B0101` (`CERT_E_EXPIRED`) for all four
modules, while `mmc.exe` was `0x0`/state 6 with signer "NT Timebomb Patch local
MMC". So the modules were still the stock Microsoft binaries: the live run had
aborted at "Cannot retain the current ...".

Cause: the retained-original copy opened its destination with `GENERIC_WRITE`
only, but `spp_copy_verified` rereads the destination to compare it, so the copy
always failed. Fixed by opening the copy with `GENERIC_READ | GENERIC_WRITE`; the
failure message now carries the Win32 code and states that the target was not
changed.

Two useful facts from the same report:

- The MMC exception installed earlier is still trusted (`0x0`, signer "NT
  Timebomb Patch local MMC"), so a local self-signature plus Root/TrustedPublisher
  is accepted by this installation.
- `osk.exe`, `Narrator.exe` and `Magnify.exe` return `TRUST_E_NOSIGNATURE`
  (`0x800B0100`) because they are catalog-signed; the `WTGetSignatureInfo` state 0
  line does not resolve catalogs, so it is not evidence about them.

## Round 6 fixes

- `/bcd` and `/bcd-show` passed the bare name `bcdedit.exe` as `lpApplicationName`,
  which fails on a trimmed WinPE PATH and under the 32-bit `System32` view. The
  tool now resolves the binary through `GetSystemDirectoryW`,
  `GetWindowsDirectoryW` and `SearchPathW`, prints the command line it runs, and
  otherwise prints the command for manual use. Verified against a synthetic ESP:
  the resolved path is launched and its own error is reported.
- `/wintrust-approval` now detects a path inside the running Windows installation
  and switches to the staged live flow (sign, trust, pending rename) instead of
  failing on a file that is in use. The detection also accepts a parent such as
  `C:\`, so the reported "Target resolves ... inside the running Windows
  installation" no longer appears for a live root.
  Verified for `C:\`, `C:\Windows` and a single live System32 DLL: each prints
  the staged-flow notice and then the elevation check.
- Key store provider failures now name the failing NCrypt call. `0x800706D9`
  (`ERROR_EPT_S_NOT_REGISTERED`) means the CNG Key Isolation service is not
  running; the signer falls back to CryptoAPI in that case.

## Target-build regressions seen in round 4

| Target | Applied | Result |
| --- | --- | --- |
| latest Windows 11 preview | `/cishim` (loader patch with the forced integrity option) | `0xc0000098` from the BCD stage |
| latest Windows 11 preview | `/cishim` (BCD option preservation only) | `0xc0000428` on the loader |
| 21390 | `/wintrust-approval` in WinPE | "Cannot create the local signing certificate (Win32 0)" |

The first failure came from the forced-integrity-option edit that `/cishim` had
started to apply on top of the option preservation; newer previews changed that
BCD handling. `/cishim` and `/cishim-boot` now apply **only** the option
preservation and refuse a loader that does not match it, while `/winload-modify`
keeps the complete gate set.

The second failure is the loader refusing the modified `ci.dll` because the entry
had no effective `nointegritychecks`. The CI patch cannot work without that BCD
option, so `/cishim` and `/cishim-boot` accept `/bcd EFI_PARTITION`, and
`/bcd`/`/bcd-show` drive `bcdedit /store` directly. The post-patch message now
states the `0xc0000428` consequence instead of a generic reminder.

The WinPE signing failure is environmental: WinPE/WinRE ship neither the software
key store provider nor an RSA cryptographic provider. On the 21390 WinPE the calls
returned `0x80090029` (`NTE_NOT_SUPPORTED`) for the key store and `0x8009001E`
(`NTE_PROV_DLL_NOT_FOUND`) for the RSA/AES provider, and the classic providers are
absent as well, so a private key cannot be created there at all. `signer.h` now
tries the key store provider, the RSA/AES provider, the enhanced and strong
providers, and the default `PROV_RSA_FULL` provider, labels every failure with its
code, and stops before any file is written when none is usable. Signing therefore
requires a full Windows installation; the offline volume can be attached to any
Windows host, and the ARM64 build of the tool can service an x64 image.

Both working paths were re-verified after the change: the key store provider signs
and WinVerifyTrust returns `0x800B0109` (valid signature, untrusted root), and with
the key store provider forced off the CryptoAPI path produces the same result.

## Local signature for the certificate modules

The 21390 and 18247 failures above showed that a byte patch of a user-mode system
DLL is rejected whatever it contains, so both `/wintrust` forms now sign the
result with a local certificate (`src/signer.h`, shared with the MMC helper) and
install that certificate as a trusted root and trusted publisher.

Verified on the host with the x64 21390 files, in a copy:

- `/wintrust-approval FOLDER` patches, strips the stale certificate table, embeds
  a new signature and re-checks it with `CryptMsgControl(CMSG_CTRL_VERIFY_SIGNATURE)`.
- `WinVerifyTrust` on the signed copies returns `0x800B0109`
  (`CERT_E_UNTRUSTEDROOT`) instead of `0x800B0100` (`TRUST_E_NOSIGNATURE`), which
  proves the new signature parses and covers the file; only the trust anchor is
  missing on a host that did not receive the certificate.
- Re-running the mode reports "already carries this package's local signature" and
  writes nothing.
- `/wintrust-approval-restore` returns both files byte-identical to the mounted
  originals and removes the retained `.bak`.
- `/cishim` and `/cishim-restore` still pass after the engine change that closes
  each handle before the post-processing step.

The offline trust path was then exercised end to end on a writable copy of the
21390 SOFTWARE hive under a synthetic offline root:

- `/wintrust-approval ROOT` patched and signed all four modules, booted `offreg`
  from `System32`, created
  `Microsoft\SystemCertificates\{Root,TrustedPublisher}\Certificates\<thumbprint>`
  with a `Blob` value, saved the hive and replaced the file; the previous hive is
  kept as `SOFTWARE.nttp-wintrust`.
- Re-opening the new hive with `offreg` returned the 763-byte DER from both
  stores, and its SHA-1 equals the thumbprint key that was created.
- `/wintrust-approval-restore ROOT` restored the four files byte-identical to the
  mounted originals, removed both certificate keys, and republished the hive.

Not verified here: the live `/wintrust` staging and pending-rename path (needs an
installed, elevated system), and whether the target's image validation accepts a
locally signed copy. Those need a VM test; the offline mode is the safe way to
try it.

## Structural matches and edits

| Mode | File | Recognized edits |
| --- | --- | --- |
| /cishim | ci.dll | CI zero-expiry leaf + build-expiry callback |
| /cishim-boot | winload.efi | image hash gate, catalog gate, revocation list, file revocation, loader integrity option, kept BCD nointegritychecks option |
| /cishim-boot | winresume.efi | same gates and forced loader integrity option; winresume has no option-removal loop |
| /cishim-boot | winload.exe (legacy) | same set as winload.efi, including the kept BCD option (the application entry is spilled through R12 instead of RBX) |
| /cishim-boot | winresume.exe | gates and forced loader integrity option |
| /wintrust | wintrust.dll | certificate time validity + validity nesting status branches |
| /wintrust | crypt32.dll | `CertVerifyTimeValidity`, `CertVerifyValidityNesting`, chain-policy expiry branch |

The crypt32 patch changes exactly six bytes plus the PE checksum: the two export
entries become `xor eax,eax; ret` and `mov eax,1; ret`, and the policy branch
`CERT_E_EXPIRED` assignment is entered from the accepted path (`7e` becomes
`eb`). The x86 SysWOW64 copies use `or dword ptr [reg], 0x01000000` and
`push 0x800B0101` forms; both are matched.

## Behaviour checked

- Repeated runs report `already patched` and write nothing.
- Restore returns every file byte-identical to the mounted original and removes
  the retained `.bak`.
- A partially patched file left by an earlier rule set is completed; the
  retained original is the patch base and a subset match is verified.
- An unsupported loader stops the run before any file is written, and no backup
  is created (checked with `ntoskrnl.exe` renamed to `winload.efi`).
- Paths inside the running Windows installation are refused.
- Hard-linked `System32\Boot\winload.efi` is patched once and reported once.
- Every patched file keeps a valid PE checksum; an unmodified rerun is
  byte-identical.

Booting the patched 21390 image, hibernation resume, and the Defender /
Narrator / Magnifier / On-Screen Keyboard start-up paths still require testing
inside that installation; this environment cannot run them.

# 5.2.1 validation

The supplied preview samples, rather than stock release CI, were used to validate the expiry modification:

| Sample | Original SHA-256 | Expiry callback RVA | Registered slot |
| --- | --- | --- | --- |
| 17746.1000 x64 | c5437546491f5e31f31284916c4494f20227cea49ea686a9a334cd341654477e | 0x4AEB0 | 0xB8 |
| 29698.1000 x64 | 61b250e6f8b3a70dbeb76f0602cf0e737b90e8d1e9fdba0d3b7aeeef708468c7 | 0x95810 | 0xB0 |

These addresses are observations from the samples. Production matching does not hardcode their addresses, hashes, or build numbers. The 17746 function identity was also checked against its Microsoft public PDB during analysis. PDBs are not needed by the tool.

File-level verification passed for both samples:

- The callback's existing entry point jumps to a zero-output, success-returning leaf in executable INT3 padding outside runtime-function ranges.
- An independent Capstone/PE inspection confirmed the entry jump, seven-byte leaf, valid PE checksum, and changes confined to those two sites plus the checksum. Each sample differs in 14 byte positions; all original unwind metadata is retained.
- Repeating the patch produces identical bytes. Two callbacks pointing to the same expiry function are rejected without exporting or writing files.
- x86 and x64 QA executables compiled from the production servicing source produced identical patched CI files. Targets deliberately omitted ntoskrnl.exe, confirming that /cishim does not need a build/version query.
- On user-owned offline fixtures, original bytes and ACLs were backed up; target ACLs, other fixture files, and read-only attributes were preserved. Conflicting backups and locked files stopped the operation, and retry after unlocking succeeded.
- Modern /image, /spponly, /spp, /nt6, and extracted /bootwim fixtures followed the LicensingUI rename and /cishim suggestion policy, skipped SPP/CI replacement, and tolerated repeat execution.
- The user's D:\ci.dll and D:\ci29698.dll retained their original hashes.

The production CLI still requires its usual privileges. After the initial UAC cancellation, the user authorized a new run and elevation succeeded. The complete production CLI test passed for both preview samples with both host binaries. Elevated DISM tests also passed for a mixed-version multi-index WIM: the older Professional index used its per-SKU flat catalogs and SPP tree, while the newer index only renamed LicensingUI and suggested the explicit CI command. The newer-image SPP-only media test rebuilt an ISO while preserving boot.wim and the root boot managers.

The CI switch was subsequently renamed from /ci to /cishim. Both production binaries passed a further elevated /cishim test on a file owned by NT SERVICE\\TrustedInstaller, with a protected DACL granting Administrators read/execute rather than write access, and the read-only attribute set. Patch, original backup, owner/DACL preservation, read-only restoration, and repeat recognition all passed. No UAC bypass was used. Read-only and CLI naming changes did not alter the expiry patch bytes.

Native x86 newer-preview and ARM64 expiry callbacks still need target testing.
The archive excludes Windows samples, patched Windows binaries, PDBs, and QA
helper executables.

## 29602 and Windows on Arm

- The 29602 x64 CI and UEFI loader both matched, and a second pass recognized
  each edit. The older 18247 loader still matched. The 28000 ARM64 retail CI
  already returns zero, and the ARM64 loader matcher recognized the supplied
  option-removal sequence. A real nonzero ARM64 preview callback and the 29602
  VM boot still need destination testing.
- The 29602 and ARM64X licensing samples match the supplied 29698 export
  profile. Native ARM64 and emulated x64 test processes loaded all five
  generated ARM64X forwarders, resolved every named and ordinal export,
  selected the correct runtime, and verified the typed default-key call.
  Settings and the complete WoA image deployment still need destination testing.

## Experimental MMC validation

The embedded signature helper checks four signature modes used by the UAC
path and requires trusted-publisher status when requesting publisher trust.
A private executable and an in-memory certificate store verified staging,
registration and repeated removal of the exact publisher certificate, and
restoration of the original executable hash.

On 18247 x64, the VM reported valid MMC signature and publisher trust while
Win+X still produced the red UAC dialog. The matching AppInfo sample places
MMC in the Windows automatic approval list and checks the Windows catalog
separately. The offline approval test removes only MMC from the list. On a
private NTFS copy, install, retry, restore and reinstall passed, and restore
recovered the original hash and security descriptor. The user then verified
that the original Win+X MMC entry opened in the 18247 VM with both stages
applied. AppInfo binary signature enforcement was in audit mode.

The release matcher reproduced the verified 18247 patch byte for byte. The
supplied x64 samples 16299.15, 22000.2600, and 29698.1000 passed install, repeat,
restore, and reinstall. Additional file tests passed on x64 samples from
10240, 14393, 22000, 26100, and 28000, the 28000 ARM64 AppInfo sample, and a
synthetic x86 PE table. Unknown files, missing table relocations, force
integrity, and two matching tables were rejected. These file tests establish
patch and rollback behavior. The 18247 run establishes the end-to-end MMC
result for that VM.

The original Build 18247 native MMC matched its Microsoft catalog by PE
signature hash. The signing certificate expired on December 14, 2018 UTC.
Both host architectures generated a separate catalog and a public certificate.
Independent checks verified the catalog signature and its certificate with an
in-memory trust store, then confirmed that Windows rejected the catalog for
the Build 18362 MMC. The host certificate store was untouched. Catalog
selection in the guest led to the embedded-signature approach below.

After the 18247 guest returned `0x800B0101`, the verifier was changed to
read the signer from the exact signature object and rebuild its code-signing
chain. The original catalog was accepted as expiry-only with Microsoft's
development root in an isolated in-memory chain engine. Verification rejected
the same catalog without that trust and rejected a different catalog under
the isolated trust.

The 18247 guest then rejected the local catalog. The system's catalog path
enforces Microsoft's root policy. The new test uses an embedded signature on
a private MMC copy with an end marker to change its signing hash. Independent
PE checks found that the original bytes only changed in the checksum and
certificate-table fields. The original catalog rejected the new SHA-1 and
SHA-256 member hashes. The Windows signature query classified the staged
copy as embedded Authenticode. A private-file transaction recovered the
original bytes and ACL.

## Experimental SLShim validation

The 29602 Settings crash dump entered `UnregisterWait` from the licensing
state handler. Its initialization exits early when `SLRegisterWindowsEvent`
fails, leaving a later wait handle uninitialized. The new register and
unregister exports were tested through the generated x86, x64 and ARM64X SLC
forwarders. The calls accept the event without signaling or closing it.
The user retested the 29602 Settings page successfully in the destination VM.

Private offline fixtures covered cleanup after a completed restore, retry
after partial cleanup, a read-only backup file, a leftover lock, and a new
install's cleanup of an old completed restore. An unrelated sibling backup
was preserved.

On a private copy of the Build 18247 SYSTEM and SOFTWARE hives, the installer
read the stock Professional default PPD and added
`DataProtectionUnderLock-WindowsCore-Enabled` as DWORD zero to both the selected
control set and the shim policy cache. The original Professional image then
completed OOBE in the guest. The subsequent SKU fix was verified on the original
Professional hive and private variants with ProfessionalWorkstation and
Enterprise edition IDs, using their original PPD files. Targeted restore
recovered the original policy byte for byte and preserved an unrelated registry
marker. Guest confirmation of the corrected SKU and watermark remains pending.

An offline hive test used a ProfessionalWorkstation EditionID with an Enterprise
composition cache in the original policy. Restore recovered SKU 0xA1 from the
matching PPD and retained an unrelated registry marker added after installation.
The restore change still needs a booted 21390 test.

The original 17746 Professional and 29698 ProfessionalWorkstation preview DLLs
and SYSTEM/SOFTWARE hives were used through private fixtures. Original samples
were retained. No upstream installer was executed, and the host's licensing DLLs,
services, ProductPolicy, and activation state were not modified.

- Both x86 and x64 host executables passed elevated production `/slshim` install,
  repeat, `/slshim-restore`, and repeated restore on both offline x64 preview
  fixtures, including all supplied x86 SysWOW64 companion DLLs. Restored DLL bytes,
  file owner/group/DACL, and CI/LicensingUI marker files were checked.
- Separate x86 and x64 API processes loaded the compiled core and all five
  forwarders for both interface profiles. Every original named export and
  ordinal resolved. Functional calls verified context open/close, right
  consumption, the 40-byte licensed-status record, genuine-state output, actual
  SKU policy reads, unknown-policy errors, and load/query/unload of an application
  policy context. The tests used a process-local registry override pointing at a
  private HKCU test key, not the host SYSTEM configuration.
- Independent file parsing compared all registry values and key security
  descriptors: 82,538 SYSTEM / 591,885 SOFTWARE records for 17746 and 103,203 /
  662,430 records for 29698. Installation changed only the intended shim keys,
  service settings, and svchost group. Targeted restore recovered all original
  records while retaining a deliberately added unrelated test key and value.
- A further elevated fixture used TrustedInstaller-owned files, protected DACLs
  giving Administrators read/execute access, and the read-only attribute on
  native/WOW64 licensing DLLs and the SYSTEM hive. Install and restore preserved
  those owners, DACLs, and attributes. Read-only transaction backups are cleaned
  up after success; the permanent original backup remains.
- Holding a later DLL open without delete sharing caused the publication phase
  to fail. Earlier published DLLs were rolled back, original hashes were retained,
  no partial runtime remained, and `/slshim-restore` recovered the prepared
  deployment. An unknown modified DLL after installation caused restore to stop
  before modifying any other target file.
- Microsoft Offline Registry Library opened and saved the supplied hives with
  both tool host architectures. The standard active-registry loading APIs had
  rejected these extracts; no original hive header repair or host SYSTEM import
  was used.

The 17746 and 29698 ProductPolicy blobs have no expiration entry. Their original SKU
feature policy is retained; absence of that entry does not prove absence of
other preview expiry checks. `/cishim` is independent. The shim's dedicated
LocalSystem service is configured offline but has not been started in a booted
target system here. OOBE, sign-in, service startup, MMC/Defender expiry behavior,
and third-party consumers of unsupported licensing APIs still need destination
VM testing. SLShim remains an experimental feature in the 5.2 release, with no
claim of universal Windows build compatibility or Microsoft activation.

## Legacy SLShim profile analysis

Four additional supplied sets were inspected through private copies. Each set
contains native x64 DLLs, x86 SysWOW64 companions, and SYSTEM/SOFTWARE hives.
Their registry EditionID values were used instead of the ProductName display
string; the 8032 hive still identifies its product as Windows 7 Ultimate.

| Sample | EditionID | Supported licensing DLLs per architecture | Existing licensing services | Kernel-ExpirationDate |
| --- | --- | --- | --- | --- |
| Vista 5483 | BusinessN | slc, slcext, slwga | SLSvc, SLUINotify | 2007-05-31 |
| Windows 7 6946 | Ultimate | slc, slcext, sppc, sppcext, slwga | sppsvc, sppuinotify | 2009-07-01 |
| Windows 8 8032 | Ultimate | slc, slcext, sppc, sppcext, slwga | sppsvc | Absent in this policy |
| Windows 8.1 9431 | Enterprise | slc, slcext, sppc, sppcext, slwga | sppsvc | Absent in this policy |

The two expiration entries are 16-byte binary values. The policy profile removes
the exact named entry, retains the other SKU feature entries, and updates the
policy's lengths. Installation now also writes the profiled policy into every
selected offline control set before first boot; the service is configured to
maintain that same cached policy later. Restore uses the saved original policy and
service start settings while retaining unrelated registry changes.

The freestanding target runtime imports only KERNEL32 and ADVAPI32. Both x86
and x64 import sets were checked against the supplied 5483 kernel32.dll and
advapi32.dll; all required direct entry points were present. No UCRT or MSVCRT
is required by the target runtime. These are static import checks, not evidence
that the DLL or its service has run successfully in a booted Vista system.

Older licensing code contains protected control flow. The ABI inspection tool
reuses maintained contracts for named interfaces instead of treating arbitrary
RET immediates as API stack cleanup. Vista SLCExt ordinals 300 through 304 were
inspected through normal frame teardown and return paths, with x86 stack cleanup
of 28, 36, 28, 40, and 16 bytes respectively (7, 9, 7, 10, and 4 32-bit slots). Unsupported
interfaces remain explicit unsupported results. Vista's slcc.dll is preserved
as the original COM component and is not part of the generic replacement set.

The updated freestanding runtime passed 12 API combinations: all six profiles
with both x86 and x64 DLL hosts. The core and existing forwarders loaded, every
named export and ordinal resolved, and functional checks passed for context
open/close, licensed status, genuine state, SKU policy queries, unknown-policy
errors, and load/query/unload of an application-policy context. Vista's expected
three-module set was handled without requiring the later SPP client DLLs.

Independent complete comparisons of registry values and key security descriptors
passed for all six profiles, covering 3,091,958 original value/security records.
They confirmed that 5483 and 6946 lose the exact
Kernel-ExpirationDate entry in the staged offline ProductPolicy, that other SKU
policies remain intact, and that restore recovers the original policy and service
settings while retaining an unrelated test key added after installation.

Additional implementation safeguards check the actual installed policy as well
as the cached copy and critical service/group settings during repeat detection.
Restore prefers a same-ID original in the complete SYSTEM backup. For a genuinely
new recognizable shim-owned clone, its possible source policies and four
licensing-service presence/start settings must be identical; ambiguous ancestry
is rejected before publication, and pruned original sets are skipped. The service loop retains one outstanding
asynchronous RegNotifyChangeKeyValue registration across a 30-second timeout,
and registers again after that notification completes.

Final elevated production CLI tests passed in all 12 combinations of the six
profiles and x86/x64 host executables: install, repeat, restore, and repeat
restore. The Vista fixture included TrustedInstaller-owned, read-only native
SLC.dll, SysWOW64 SLCExt.dll, and SYSTEM hive files. Their owner, group, DACL,
attributes, and last-write time were preserved. Unrelated files, including
Vista's original SLCC.dll, remained unchanged.

Additional production checks passed:

- Replacing the installed policy with the original expiration-bearing policy
  caused repeat detection to refuse the stale installation.
- Restoring a new ControlSet999 clone succeeded for 5483 with the x64 host and
  6946 with the x86 host. A fixture with ambiguous original ControlSet998 source
  settings and a new ControlSet999 was rejected before target writes.
- Reusing originally unselected ControlSet002 restored its own saved service
  Start value of 3, rather than ControlSet001's value of 2.
- Notification mocks passed all 12 combinations, observing two registrations
  across six waits. This checks the notification-loop behavior without starting
  an actual Windows service.

Private-key policy-refresh probes completed RegSaveKeyEx, RegLoadAppKey,
RegSetValueEx, and key close successfully. RegRestoreKey with flags 8 and 0
returned Win32 error 1 and observed NTSTATUS 0xC0000002 for HKCU targets, in
emulated x86/x64 processes and a native ARM64 probe. An application-hive target
returned 19 / 0xC0000189; an attempt to mount a fresh private hive under HKLM
returned 87 / 0xC000000D. The cause has not been established. These probes do
not establish successful live kernel-policy refresh, and the production service
refresh algorithm has not been changed to bypass these results. All private
fixtures were cleaned up successfully; the host's actual SYSTEM, SPP, and SCM
configuration was not changed.

Destination VM tests must still cover service startup, early boot, OOBE,
sign-in, and behavior after the original expiry date. An absent policy expiration
entry in 8032 or 9431 does not prove that other expiry checks are absent. The
formal 5.2 package is tagged v5.2.0; the v5.2 preview tag remains unchanged.

## Build 18247 diagnostics

- A supplied UEFI VM with Secure Boot disabled returned `0xc0000428` with the modified CI. Restoring only the original CI allowed that VM to boot. The modified CI in the offline mount matched the locally generated patch byte for byte, and Authenticode returned `HashMismatch`. The VM's active EFI and BCD have not been inspected.
- Both offline hives in the 18247 mount returned Win32 32 while loaded under the host registry. After the hives were released, copies of both were readable. On private copies, holding either `SYSTEM` or `SOFTWARE` open exclusively reproduced Win32 32 and reported the exact file without producing staged hives or changing the inputs. With the handles closed, staged registry installation and targeted restore passed, including preservation of an unrelated setting. This did not exercise VM boot or OOBE.
- On the supplied 18247 x64 loader, `/cishim-boot` changes the five-byte call that removes `nointegritychecks` and updates the PE checksum. The loader's original hash, backup permissions, read-only attribute, repeat recognition, and rejection of the supplied `bootmgfw.efi` under a loader filename were checked. The user verified normal UEFI boot with both patches and `nointegritychecks on`, and reported working personalization and Defender and removal of the preview watermark and expiry time.
- The SLShim ACL update was checked by reading the staged 18247 SYSTEM hive and by applying the shim file DACL to a private test file. Both application-package principals have read-only access to the policy key and read/execute access to the file. The 18247 `ProductPolicy` change remained the single byte for `Kernel-NonGenuineNotificationType`. The Start menu and OOBE need destination VM tests.
- The original `/cishim-boot` guard rejected an offline loader if the running environment had no `System32\winload.efi`. A fixture with that layout reproduced the failure. After the fix, the 18247 loader patched and backed up successfully, including when the running Windows directory was on a separate volume and the offline loader had two hard links. A hard link to the running loader was still rejected. A missing offline loader reported its path and Win32 error 2.
- Integrated `/cishim` produced the same CI and loader hashes as the separately tested commands. Repeating it, upgrading from an already-patched CI, and falling back to the CI patch when the loader was missing or unsupported all passed. With a simulated partial write to CI after updating the loader, both original hashes and the loader's read-only attribute were restored.
