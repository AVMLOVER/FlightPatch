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
