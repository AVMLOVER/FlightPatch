# NT Timebomb Patch 5.3.0

Chinese documentation: [README.zh-CN.md](README.zh-CN.md).

Run `nttimebomb.cmd /version` to identify the local build. The executable's
Details tab also shows its file and product versions.

Version 5.3.0 patches the preview CI expiry callback together with every boot
loader the image uses: `winload.efi`, `winresume.efi` and the legacy
`winload.exe`/`winresume.exe`, including their `System32\Boot` hard links. The
same commands accept an offline Windows root, a folder of separately extracted
files, or one single file. `/winload-modify` patches the release loader of a
dual-boot EFI or BIOS installation so it accepts the modified image. `/bcd` and
`/bcd-show` set and print the boot options the CI patch needs, `/bcd-template` does
the same for the BCD template inside an image, and `/slshim` replaces the licensing
layer. Every changed file keeps a verified `.bak`, and
`/restore` puts the originals back.

NT Timebomb Patch is an offline command-line tool for Windows prerelease images. It replaces NT6 licensing tokens and optional Branding, services older FlightSigned boot files, processes installation media, and rebuilds BIOS/UEFI ISOs with Microsoft OSCDIMG. The former FlightPatch command name remains available as a compatibility launcher.

## Requirements and permissions

Extract the complete ZIP into a new directory. Run nttimebomb.cmd from an elevated Command Prompt on Windows, or a LocalSystem command prompt in Windows PE. The launcher selects the x86, x64, or ARM64 executable for the current environment. The target architecture is detected separately. Use local drive paths shorter than MAX_PATH and quote paths containing spaces.

For protected files, open a new privileged prompt with NSudo, change to the tool directory, and run the command there. Administrator elevation with backup and restore privileges is normally sufficient on Windows. In WinPE, use SYSTEM.

~~~bat
NSudoLC.exe -U:S -P:E cmd.exe
NSudoLC.exe -U:T -P:E cmd.exe
nttimebomb.cmd /help
~~~

WIM servicing uses Windows DISM. ISO creation requires OSCDIMG from the Microsoft Windows ADK. ISO input additionally requires 7z.exe and its runtime files from 7-Zip. Place dependencies beside the executable, add them to PATH, or specify /oscdimg and /7zip. Only ISO extraction requires 7-Zip. Only ISO creation requires OSCDIMG.

## Explicit CI build-expiry patch

Use /cishim with an already mounted or deployed offline Windows root, a folder of separately extracted System32 files, or one single file. Supply the directory containing Windows; a flattened extraction such as `ci.dll`, `winload.efi`, `winresume.efi` in one folder is also accepted.

~~~bat
nttimebomb.cmd /cishim D:\Mount
nttimebomb.cmd /cishim W:\ /bcd S:\
nttimebomb.cmd /cishim D:\Extracted
nttimebomb.cmd /cishim D:\Extracted\ci.dll
~~~

The modified `ci.dll` is loaded by the loader, which rejects it with `0xc0000428`
unless the target entry has `nointegritychecks` on and Secure Boot is off. Add
`/bcd EFI_SYSTEM_PARTITION` to the command, or set it yourself:

~~~bat
nttimebomb.cmd /bcd S:\
nttimebomb.cmd /bcd S:\ {GUID-OF-THE-TEST-ENTRY}
nttimebomb.cmd /bcd-show S:\
~~~

`/bcd` and `/bcd-show` drive `bcdedit /store` against the offline BCD on that
partition; `{default}` is used when no entry GUID is given. `/bcd` writes two
elements in one run:

- `nointegritychecks on`, which the loader needs to accept the patched `ci.dll`;
- `recoveryenabled No`, so a failed attempt stops in the boot menu instead of
  starting the automatic repair, which would rewrite the store and drop the flag.

`/bcd-show` enumerates the entry and prints both elements explicitly, because
`bcdedit` hides default values in the plain enumeration.

This is separate from the loader patch on purpose: the CI patch must not be applied
without the boot option. The tool resolves `bcdedit.exe` through the system
directory, the Windows directory and `PATH` before launching it, prints the exact
command line it runs, and falls back to telling you the command to run by hand. A
trimmed WinPE PATH or a redirected 32-bit view no longer breaks it.

For image building, `/bcd-template OFFLINE_ROOT` writes the same two elements into
`Windows\System32\config\BCD-Template`, so newly created stores on a deployed
image already carry them:

~~~bat
nttimebomb.cmd /bcd-template D:\Mount
~~~


The command prepares `Windows\System32\ci.dll` plus every boot loader it finds: `winload.efi`, `winresume.efi`, the legacy `winload.exe` and `winresume.exe`, and their `System32\Boot` copies. A missing, mismatched, or unsupported winload stops the operation before CI is written; the two `Boot` copies are recognised as hard links to the same files and patched once. The loader part is deliberately small: it keeps the explicit `nointegritychecks` BCD option through `OslPrepareTarget` and nothing else. It does not force the loader's own integrity option, and it does not touch the image-hash, catalog or revocation gates; those belong to `/winload-modify` and to the older `/image` flow. Newer previews changed that BCD handling, and the extra forced-option edit made such a build stop with `0xc0000098`, so a loader that does not match the option-preservation structure is now refused instead of patched. `winresume` has no option-removal loop and therefore matches nothing; it is reported and left unchanged. The legacy `winload.exe` keeps the explicit BCD option exactly like the UEFI loader, which is what a BIOS boot needs after the CI patch. It identifies compatible layouts without a build-number check. On Build 15063 and newer the legacy `/image` flow makes no change at all and points at `/cishim` and `/slshim`; the CI patch itself has no build boundary.

Single files are matched by structure, not by name: `/cishim FILE` recognises the CI expiry callback in a `ci.dll` and the loader rules in a `winload`/`winresume` image. Use `/cishim-boot` to apply only the loader rules.

The expiry principle comes from [gailium119/cishim](https://github.com/gailium119/cishim/blob/c0ec25dbcb8e11109e24297c40d72c2ab6b24a8d/cishim/cishim.c): its CiGetBuildExpiryTime callback writes zero to the output and returns success. NT Timebomb Patch implements that behavior independently in the original CI. It identifies the preview's self-image expiry routine and confirms that CiInitialize registers it as a callback. The supplied preview 17746 and 29698 samples use different callback-table slots, both of which are checked structurally. An entry jump redirects to a small leaf routine in verified INT3 padding outside unwind-function ranges; the original unwind tables and other CI callbacks are retained. The full cishim module and its other signature-validation stubs are not bundled.

Newer preview CI replacement has file-level validation on the supplied x64 samples. The ARM64 build recognizes the already-zero callback on the supplied 28000 retail sample and skips writes. A nonzero ARM64 preview callback still needs an original preview sample. Missing anchors, ambiguous matches, or unavailable leaf space stop the operation before writing.

Before writing, the tool saves a `.bak` copy beside each file it will patch, with verified contents, owner, group, DACL, inheritance protection, and last-write time. It prepares and locks every changed file before writing any of them. A write failure attempts to restore the original bytes. Existing backups are never overwritten and are used as the patch base, so a newer build can finish a patch that an earlier build left partially applied. Re-running `/cishim` recognizes existing patches. `/restore` puts the retained originals back; see [Restore the retained originals](#restore-the-retained-originals).

The patch changes a signed system binary; it does not regenerate Microsoft's signature or configure Secure Boot, HVCI, BCD, or the selected boot manager. The target boot chain must accept the modified file. Verification with the supplied preview files checks structural matching, patch bytes, checksum, repeat behavior, permissions, and file scope. Booting an expired preview and confirming MMC/Defender behavior still requires testing in that target system; stock release CI is not evidence of preview-expiry removal.

On Build 18247 in a UEFI VM, the modified CI failed to boot with `0xc0000428`. Startup Settings option 7 (Disable Driver Signature Enforcement) allowed that boot. Ordinary boot failed again on restart. In the supplied 18247 `winload.efi`, `OslPrepareTarget` removes the `nointegritychecks` BCD option and the advanced boot menu can add it back later for a single session.

### UEFI boot setup for 18247

The matched loader patch preserves the explicit BCD option through its
preparation step. The supplied 18247 loader with this patch and
`nointegritychecks on` was verified on a UEFI VM without pressing F7. The
older `/cishim-boot` command is still available if you need to patch just
the loader. Normally `/cishim` applies both parts in one operation.

Use a VM snapshot with Secure Boot disabled and Windows already installed. Start
WinPE and identify the Windows partition (here `W:`) and the EFI System Partition
(here `S:`). Confirm that the BCD entry uses `W:\Windows` and `\Windows\System32\winload.efi`.
Use the actual entry GUID in place of `{default}` if needed. The example is for CMD.

~~~bat
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum {default}
bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} nointegritychecks on
nttimebomb.cmd /cishim W:\
~~~

The loader backup is `Windows\System32\winload.efi.bak`. The BCD commands
apply to the selected Windows entry. Recovery can remain enabled. If boot fails, restore the snapshot or use
WinPE to run `nttimebomb.cmd /restore W:\` and remove the original BCD setting. If
`nointegritychecks` was absent before the test, remove it with
`bcdedit /store S:\EFI\Microsoft\Boot\BCD /deletevalue {default} nointegritychecks`.
`check-boot` can inspect loaders and a supplied EFI System Partition without writing.

## UIACCESS programs that will not start

`osk.exe`, `Narrator.exe` and `Magnify.exe` fail on an expired preview build with a
plain error dialog carrying `ERROR_DS_REFERRAL` (8235), not a UAC prompt. Measured on
21390, four different repairs do not help: a locally signed `wintrust.dll`/`crypt32.dll`,
a manifest without `uiAccess`, a patched `consent.exe` and AppInfo auto-approval
entries. Disabling the LUA subsystem is what makes them start:

~~~bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
        /v EnableLUA /t REG_DWORD /d 0 /f
:: restart
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ^
        /v EnableLUA /t REG_DWORD /d 1 /f
~~~

Lowering the UAC slider is not enough: `EnableLUA` has to be `0`, which removes the
filtered token, the consent prompt and the uiAccess token request altogether. The
costs are real: no UAC prompt at all, every process gets the full administrator
token, and Store/UWP applications stop starting. The package therefore does not
automate it.

Windows Defender's service (`WinDefend`) is a separate problem: it starts and then
terminates (event 7034) with an empty own log, which is the platform refusing to run
on this build. No repair is offered.

## Release loader patch for a dual-boot system

A release Windows installation keeps a loader of its own: `\EFI\Microsoft\Boot\winload.efi`
on the EFI System Partition, or `\Windows\System32\winload.exe` for a BIOS start. A
dual-boot entry that starts the modified image through those files fails, because the
release loader applies the same expired-image gates as the preview loader.

~~~bat
nttimebomb.cmd /winload-modify S:\
nttimebomb.cmd /winload-modify S:\ C:\
~~~

The first form services `EFI\Microsoft\Boot\winload.efi` and `winresume.efi` on the
supplied partition and stops if that partition holds no EFI loader. The optional
second path also services `bootmgr`, `Boot\winload.exe`, `Boot\winresume.exe` and
`Windows\System32\winload.exe|winresume.exe` for legacy boot. The rules are the same
structural matchers as `/cishim-boot`, so an unsupported file is reported and skipped
rather than guessed, and a changed EFI loader is written before the legacy volume is
examined.

## Restore the retained originals

Every mode keeps a verified copy of the original beside the file it changes.

~~~bat
nttimebomb.cmd /restore D:\Mount
nttimebomb.cmd /restore D:\Mount\Windows\System32\ci.dll
~~~

`/cishim-restore`, `/cishim-boot-restore` and
`/winload-modify-restore` select which set to clear on the supplied root, folder, or
single file: `/cishim-restore` restores `ci.dll` together with all four loaders,
`/cishim-boot-restore` and `/winload-modify-restore` restore the loaders only, and
`/restore` clears every retained original. Restore writes the retained bytes back,
re-applies the retained owner, DACL and attributes, verifies the result, and removes
that backup. A file that already matches its retained original is reported and left
alone, and a file without a backup is not touched. Packages before this one used the
suffix `.nttp-original`; that name is still read. Restore needs an elevated or SYSTEM
prompt to re-apply ACLs on protected system files; without those rights it restores
the contents and says that the permissions were left as they are.

Restore is also the recovery path for a partially applied patch: the retained
original is the base for every write, so a newer build finishes a file that an older
build patched only in part. A file that matches neither its retained original nor the
result of the current rule set is refused with a message, and the backup is kept.

## MMC certificate-expiry repair (deprecated)

`/mmc` and `/mmc-approval` are deprecated and will be removed in the next release.
They were written for an expired-certificate failure of `mmc.exe` and AppInfo; the
programs that could not start are a LUA problem, solved by `EnableLUA=0` (see the
UIACCESS section). The modes still work but print a deprecation notice, and the
AppInfo auto-approval entries for `osk.exe`, `Narrator.exe` and `Magnify.exe` have
been withdrawn.

Use both steps on a test installation whose original MMC is blocked by an
expired catalog signature. The two commands cover the MMC publisher check and
the separate AppInfo automatic elevation check.

### 1. Install the local MMC signature in Windows

After completing OOBE and reaching the desktop, open an elevated Command Prompt
inside the test Windows installation and run:

```bat
nttimebomb.cmd /mmc
```

The command checks the running system's native `System32\mmc.exe` and requires a
matching Microsoft catalog signature whose sole trust error is certificate
expiry. It stages a copy of that executable with an embedded local signature.
A marker at the file end gives it a different signing hash so Windows takes
the embedded signature path. The executable's code and resources are kept.
The command adds the public certificate to `LocalMachine\Root` and
`LocalMachine\TrustedPublisher` after releasing the signing key. It checks
signature and publisher trust before and after publication. The original
executable is saved under `%SystemRoot%\NTTP-MMC-*\original.exe`. Keep the
native MMC helper beside the main executable. Images with an existing embedded
MMC signature or force-integrity protection are outside this mode's scope.

### 2. Service AppInfo in WinPE or from another Windows installation

Shut down the target after `/mmc` succeeds. From a SYSTEM Command Prompt in
WinPE, or an elevated prompt in another Windows installation, run:

```bat
nttimebomb.cmd /mmc-approval W:\
```

Replace `W:\` with the deployed NTFS volume or offline root containing
`Windows\System32\appinfo.dll`. The tool identifies the sorted approval table
and verifies its PE pointer relocations without a build-number or fixed-offset
check. It removes only MMC from the list so it can use normal UAC confirmation.
Unknown and ambiguous layouts stop before replacement. The target must permit
the modified AppInfo to load. On the tested 18247 VM, AppInfo's
`MicrosoftSignedOnly` process setting was off and auditing was enabled.

Boot the target and open **Disk Management from Win+X** to check the original
entry and UAC prompt. The full two-stage flow passed on 18247 x64. The supplied
16299, 22000, and 29698 x64 files passed offline patch and restore tests.

### Roll back both stages

In WinPE or from another Windows installation, restore the original AppInfo:

```bat
nttimebomb.cmd /mmc-approval-restore W:\
```

AppInfo's original NTFS file and permissions are kept at
`Windows\System32\appinfo.dll.nttp-mmc-original`. Then boot the target and run
`nttimebomb.cmd /mmc-restore` in an elevated prompt to restore MMC and remove its
local certificate. Restore both stages before servicing the original files
with a system update. Either restore stops if the installed file has changed.

## Experimental SLShim licensing-layer replacement

Use `/slshim` to install an independent replacement for the Windows licensing
client layer into a mounted or deployed **offline** Windows root. This is the
full replacement mode: it disables the target's existing licensing services and installs a
dedicated LocalSystem service. It is separate from donor-based `/spp` replacement.
No donor directory, product key, tokens.dat, or additional switch is required.

~~~bat
nttimebomb.cmd /slshim D:\Mount
nttimebomb.cmd /slshim-restore D:\Mount
~~~

`D:\Mount` must contain `Windows\System32\Config\SYSTEM` and `SOFTWARE`, along
with the target's original licensing DLLs. A flat extraction such as the analysis
samples is not a deployable target. Use Windows 10 / WinPE 10 or newer as the
servicing host. Keep the complete `slshim` and `dependencies` directories beside
the executables. The tool selects target architecture separately from host
architecture. For the supplied Windows on Arm interface, the package includes
ARM64X forwarders for native ARM64 and emulated x64 applications plus the x86
payload for SysWOW64. Matching checks the original export names and ordinals.

Win32 error 32 is a sharing violation. Check whether the named offline registry
hive is still loaded by the servicing utility or by a manual registry mount.
Close the utility or unload the hive you loaded before retrying. Running as
SYSTEM does not clear the lock. A failed registry preflight can leave a zero-byte
`operation.lock`; that file alone is not evidence of installation. Look for the
successful install message and `NTTimebombBackup\SLShim\state.bin`.
The parent `NTTimebombBackup` directory has the Hidden and System attributes.

The offline installer checks the target edition's default PPD license for
`DataProtectionUnderLock-WindowsCore-Enabled`. When the original SKU file sets it
to zero and `ProductPolicy` lacks it, SLShim includes that default in the policy
installed for the first boot. Build 18247's AppX state extension queries this
value while registering OOBE and the Start menu. The same rule fills in the
stock zero for `shell32-license-ShowProductNameOnDesktop`, which the 18247 shell
otherwise treats as an instruction to draw the product-name watermark.

SLShim uses the offline image's `EditionID`. If its cached kernel identity
still matches a different `CompositionEditionID`, the installer reads the
original PPD for the selected SKU and corrects its kernel edition, product
and branding values. For example, a Professional image may initially contain
an Enterprise composition cache. The original registry edition and composition
metadata are retained. To update an earlier SLShim install, restore it in
WinPE and reinstall with the new package. A successful restore clears SLShim's
backup and removes the parent directory when it is empty. A new install can
also clear a completed restore left by an earlier package.

The installer checks the original export names and ordinals before allowing a
replacement. These interface profiles are included:

| Supplied sample | EditionID | Licensing services present | ProductPolicy expiration entry |
| --- | --- | --- | --- |
| Vista 5483 | BusinessN | SLSvc, SLUINotify | Kernel-ExpirationDate: 2007-05-31 |
| Windows 7 6946 | Ultimate | sppsvc, sppuinotify | Kernel-ExpirationDate: 2009-07-01 |
| Windows 8 8032 | Ultimate | sppsvc | Not present in the supplied policy |
| Windows 8.1 9431 | Enterprise | sppsvc | Not present in the supplied policy |
| Windows 10 17746 | Professional | Existing SPP services | Not present in the supplied policy |
| Windows 11 29698 | ProfessionalWorkstation | Existing SPP services | Not present in the supplied policy |

The supplied sets contain native x64 DLLs and their x86 SysWOW64 companions.
Matching is based on the DLL interface, rather than a minimum or maximum Build
check; an unverified interface is rejected. A profile identifies an analyzed
interface and does not establish that every consumer or expiry mechanism in that
Windows build has been tested.
The numeric payload subdirectories identify the analyzed interface profiles.
Do not rename them or mix DLLs from another package. Payload fingerprints are
checked before deployment.

This implementation follows the layer-replacement principle in
[shakenetwork/slshim](https://github.com/shakenetwork/slshim/tree/14bae9b2bf82bd4c28c4172955c0e7c92988ac43),
with independently written servicing and runtime code. It replaces the existing
`slc.dll`, `slcext.dll`, `sppc.dll`, `sppcext.dll`, and `slwga.dll` in System32
and, where present on an x64 target, SysWOW64. Small forwarders preserve each
original module's export names and ordinals and load the matching
`nttp-slshim.dll` runtime. Original file owners, groups, DACLs, last-write times,
and attributes are retained. Added runtime DLLs are TrustedInstaller-owned and
readable/executable by users.

Vista 5483 supplies `slc.dll`, `slcext.dll`, and `slwga.dll`; missing `sppc.dll`
and `sppcext.dll` is expected for this set. The installer handles those existing
supported modules. `slcc.dll` remains the original COM component. This mode does
not replace every file whose name starts with `sl` or `spp`.

The target runtime imports only KERNEL32 and ADVAPI32 and has no UCRT or MSVCRT
dependency. Its required imported entry points were checked against the supplied
5483 DLLs for both architectures. The servicing executable still runs from the
Windows 10 / WinPE 10 or newer host described above; this import check does not
replace a booted-target compatibility test.

The offline SYSTEM hive supplies that target SKU's ProductPolicy. The shim
preserves its feature policies, removes an exact `Kernel-ExpirationDate` entry
if present, and clears `Kernel-NonGenuineNotificationType` if present. During
installation the resulting policy is written into each selected offline control
set, so an older kernel can read it before the shim service starts. The same
policy is cached in the protected `SYSTEM\NTTimebombSLShim` key for the service
refresh path after boot. Other SKU feature policies are retained.

An absent expiration entry does not establish that the build has no other expiry
checks. `/cishim` remains a separate command for a supported CI structure. For a
newer preview with a verified CI interface, such as the supplied 17746 or 29698:

~~~bat
nttimebomb.cmd /cishim D:\Mount
nttimebomb.cmd /slshim D:\Mount
dism /Unmount-Image /MountDir:D:\Mount /Commit
~~~

The installer detects the target's existing `sppsvc`, `sppuinotify`, `SLSvc`, and
`SLUINotify` services and disables those present. At least one core licensing
service (`sppsvc` or `SLSvc`) is required; absent services are not created. A dedicated
`NTTimebombSLShim` svchost group and service are created; the service is configured to maintain
the cached kernel policy after the target boots. It does not share the
DcomLaunch group and does not change Office's `osppsvc`. The local runtime
reports licensed/genuine status and answers policy queries from that SKU's
cache. Unknown policies return an error. Unsupported activation, ticket, COM,
and other private interfaces return an explicit unsupported result; this mode
does not issue a Microsoft digital license or implement online activation.

Runtime policy refresh still needs a target-system test. Private registry probes
on this host completed snapshot saving and editing, but the RegRestoreKey step
failed in x86, x64, and native ARM64 probes; the cause is not established.
See `TESTING.md` for the results. Actual SCM startup, boot, OOBE, sign-in, and
behavior after expiry remain unverified in a destination VM.

### SLShim backup and restore

Before target files are published, originals are copied to
`OFFLINE_ROOT\NTTimebombBackup\SLShim`. Keep that directory with the image.
It contains verified original DLLs and hives, original file metadata, and the
deployment manifest. Existing original backups are not overwritten. Repeating
an intact installation reports that it is already installed after validating the
installed DLLs, cached policy, current control-set ProductPolicy, and critical
service and svchost-group settings. A stale original expiration policy or an
incomplete configuration is rejected instead of being reported as installed.
An interrupted prepared deployment can be restored with the same command shown
below.

~~~bat
nttimebomb.cmd /slshim-restore D:\Mount
~~~

Restore puts back the original DLLs and removes the added runtime DLLs. It
restores the saved licensing service start settings and ProductPolicy, and removes
the shim service, cache, and svchost group. It edits the current offline hives
instead of copying an old complete hive over them, preserving unrelated registry
changes made since installation. Restore uses the saved ProductPolicy. If its
cached SKU matches the composition edition and differs from the installed
EditionID, restore corrects the SKU identity fields using the installed
edition's matching PPD license. If those values cannot be verified, restore
keeps the saved policy and reports the fallback.
Unknown changed licensing DLLs or a changed OS edition/build stop
restore to avoid downgrading a serviced installation. Backups remain after a
successful restore. Archive the restored `SLShim` backup directory before a
fresh installation; the tool deliberately does not replace its original backup.

Windows may create another LastKnownGood control set after installation. Restore
also discovers additional control sets containing the recognizably owned shim
service. A set with the same ID in the complete original SYSTEM backup uses
its own saved policy and service settings, including a set that was unselected
at installation. A genuinely new clone can use a saved source only when the
original selected source sets have identical ProductPolicy bytes and identical
presence/start settings for all four licensing services.
If those sources differ, restore stops before publishing files rather than
guessing which original belongs to the clone. Original control sets that Windows
has pruned are skipped; restore does not recreate deleted control-set trees.

`/slshim` accepts an offline directory only. It does not implicitly run from
`/image`, `/media`, or `/spponly`, and it does not process WIM/ISO filenames or
all WIM indexes. Mount the intended index, run it explicitly, and commit the
mount yourself. The mode leaves CI, boot files, kernels, LicensingUI, SPP token
trees, and CatRoot unchanged. Target boot/code-integrity policies must accept
the replacement DLLs. File/API validation is recorded in `TESTING.md`; booting,
OOBE, login, and expired-application behavior require testing in the target VM.

## NT6 tokens and optional Branding

Use /nt6 to replace the SPP tokens tree, with optional Branding detected automatically. /file identifies the donor folder. /target identifies an offline Windows root containing Windows\System32\Config\SYSTEM.

~~~bat
nttimebomb.cmd /nt6 /file D:\Donor /target W:\
flightpatch.cmd /nt6 /file "D:\Donor\Windows\System32\spp\tokens" /target D:\Mount
~~~

The donor may contain Windows\System32\spp\tokens, System32\spp\tokens, spp\tokens, or tokens. You may also point directly to a directory named tokens. Supply one unambiguous tokens tree.

Tokens are written into target Windows\System32\spp\tokens. Matching files are replaced. Target-only tokens remain. NT SERVICE\sppsvc receives Full Control on the tokens directory, every subdirectory, and every file, including target-only items. Other existing access rules and target owners are retained.

If the directory supplied to /file also contains Branding, the tool automatically copies its contents to target Windows\Branding. A complete image donor may provide Windows\Branding instead. Supply only one of those layouts. Every target Branding folder and file receives NT SERVICE\TrustedInstaller Full Control, including inheritance for new children. Matching files are replaced and target-only files remain. Existing owners are retained. When no Branding directory is supplied, this step is skipped.

For example, D:\Donor\spp\tokens and D:\Donor\Branding can be provided together. There is no separate Branding switch.

~~~bat
nttimebomb.cmd /nt6 /file D:\Donor /target D:\Mount
~~~

The same automatic detection applies to /media ... /nt6 D:\Donor in every install.wim index. Tokens and Branding are staged together, so a failure in either tree triggers rollback of both files and permissions.

Below Build 15063, NT6 mode does not replace SPP binaries, CatRoot, the store database, or SysWOW64. It does not patch CI, boot managers, loaders, or kernels, and does not rename LicensingUI. Supply tokens appropriate for your target. Files are staged and verified before publication. On failure the tool attempts to restore original files and directory permissions. For a detected Build 15063 or newer the mode refuses to run at all: nothing is changed and the tool asks for /cishim (CI) and /slshim (licensing) instead.

## Complete installation media to a new ISO

/media accepts a Windows installation ISO or its extracted directory. This is different from a mounted Windows image. The source must contain root bootmgr and bootmgr.efi, sources\boot.wim, sources\install.wim, boot\etfsboot.com, and efi\microsoft\boot\efisys.bin.

~~~bat
nttimebomb.cmd /media D:\Preview.iso /work D:\NTTP-Work /out D:\Preview-patched.iso /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe
nttimebomb.cmd /media D:\ExtractedDVD /work D:\NTTP-Work2 /out D:\Preview-patched2.iso /oscdimg C:\Tools\oscdimg.exe
~~~

Both /work and /out must be new paths. Keep them outside the source directory, and keep the output outside the workspace. The source is preserved. Allow enough local NTFS space for the media copy, DISM staging, and output ISO.

For replacement-only media processing, provide the donor immediately after /spponly or /nt6. These options are mutually exclusive with each other and with /spp.

~~~bat
nttimebomb.cmd /media D:\Preview.iso /work D:\SPP-Work /out D:\Preview-spp.iso /spponly D:\RTM-SPP /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe
nttimebomb.cmd /media D:\Preview.iso /work D:\Tokens-Work /out D:\Preview-tokens.iso /nt6 D:\Donor\spp /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe
~~~

Both combinations service every install.wim index and rebuild the ISO. Below Build 15063, /spponly uses standard SPP replacement, including its SysWOW64 handling, CatRoot rules and exclusions; /nt6 copies System32 SPP tokens with SPPSVC access and automatically applies optional Branding with TrustedInstaller access. Both preserve boot.wim, root boot managers, CI, loaders, and kernels. Build 15063 and newer indexes are refused without any change and the tool points at /cishim and /slshim. The original /media /spp combination still performs the full older boot-patching workflow.

The tool performs the following operations.

1. Extract the ISO with 7-Zip, or copy the media tree to the private workspace.
2. Mount, service, and commit every boot.wim index.
3. Mount, service, and commit every install.wim index.
4. Patch root Legacy bootmgr and UEFI bootmgr.efi for supported older media.
5. Build a dual BIOS/UEFI UDF ISO with OSCDIMG using the original El Torito boot images.

For older images, the normal offline workflow also handles existing Windows boot managers, loaders, CI, hvloader, and WinRE. Main-system and WinRE kernels remain unchanged. Optional /spp D:\RTM-SPP replaces SPP in every install.wim index, but does not apply the donor to boot.wim. For multi-index install.wim, use the shared-binary and per-SKU donor layout below. /media ... /spponly uses the same SKU selection. /nt6 keeps its existing tokens/Branding donor layout.

Standalone boot.wim and install.wim files are required. Convert SWM or ESD media to WIM before using this mode. Unsupported boot-file structures stop the operation. The final ISO is published only after OSCDIMG succeeds. The workspace remains for inspection and manual cleanup. Failure may leave a partial ISO with .partial- in its name.

## Patch two supplied boot managers

Place bootmgr and bootmgr.efi together in one input directory, and choose a new output directory. Both files are required and both are prepared and verified before the output folder is published. Deploy the results to the matching installation media.

~~~bat
nttimebomb.cmd /bootfiles D:\OriginalBootFiles /out D:\PatchedBootFiles
~~~

## Service one offline Windows installation

/image accepts a mounted DISM image or Windows partition. Use /boot for its separate ESP or Legacy boot volume, and /recovery for a separate recovery volume. If you manually mounted the outer image, commit it yourself afterward.

~~~bat
nttimebomb.cmd /image D:\Mount
nttimebomb.cmd /image W:\ /boot S:\ /recovery R:\
nttimebomb.cmd /image D:\install.wim /index 4 /out D:\install-patched.wim
~~~

WIM input requires a new /out path. /image and /spponly default to index 1. Use /index all to service every index, or /index N to select one. /media also services all installation indexes. Supported earlier files are identified using PE structure and code patterns. The existing matcher does not require a build number or PDB.

### Use /image with /spp for older preview expiration

For an older supported FlightSigned build, combine /image with /spp when you want the normal offline boot-expiration patches and the replacement SPP files in the same operation. /image selects the target Windows installation. /spp selects your separately prepared donor files. It does not name a temporary directory or the destination.

Prepare a donor from the appropriate released Windows version and architecture. A flat example has D:\RTM-SPP\sppsvc.exe, the other selected spp* binaries, D:\RTM-SPP\spp, and selected CatRoot certificates or catalogs. For an x64 target, add the corresponding x86 files under D:\RTM-SPP\SysWOW64. The standard SPP exclusions listed below still apply.

To modify an existing install.wim, first identify its indexes and mount the edition you want. The mount directory must be empty. Run these commands from the privileged command prompt described above.

~~~bat
dism /Get-ImageInfo /ImageFile:D:\install.wim
mkdir D:\Mount
dism /Mount-Image /ImageFile:D:\install.wim /Index:1 /MountDir:D:\Mount
nttimebomb.cmd /image D:\Mount /spp D:\RTM-SPP
dism /Unmount-Image /MountDir:D:\Mount /Commit
~~~

Replace index 1 with the desired edition. Check that NT Timebomb Patch reports success before committing. If it fails, inspect its output before deciding whether to retry or discard the mounted image. The tool validates the SPP donor first, processes the older image's boot and recovery files, and then applies standard SPP replacement. If the final SPP step fails after boot processing, its output says so, and you can retry the SPP operation.

You can instead let the tool mount a private WIM copy and create a new output file. The source WIM is retained, and a successful command has already committed the selected output index.

~~~bat
nttimebomb.cmd /image D:\install.wim /index 1 /out D:\install-patched.wim /spp D:\RTM-SPP
~~~

For an already deployed offline system, identify its Windows volume and its actual EFI or Legacy system partition. In the following example, W: contains the target Windows directory and S: is that system's boot partition.

~~~bat
nttimebomb.cmd /image W:\ /boot S:\ /spp D:\RTM-SPP
~~~

Add /recovery R:\ when the target WinRE is on a separate recovery volume. Main-system and WinRE kernels are retained by /image. The result must still be tested with the boot manager actually selected by firmware. In particular, a VHDX can use the physical machine's ESP rather than the boot files inside the VHDX.

For complete installation media and all install.wim editions, use /media with /spp and an appropriate donor. That combination performs the full older boot-patching workflow. The /media /spponly and /media /nt6 combinations perform replacement-only experiments instead.

### Build 15063 and newer

For normal /image, /spponly, /spp, /spp-reference, /nt6, /bootwim and /media image processing the legacy FlightSigned work applies to Build 15063 and older only. On Build 15063 or newer the mode makes no change at all, not even renaming LicensingUI.exe, and tells you to run nttimebomb /cishim OFFLINE_ROOT for the CI restrictions and nttimebomb /slshim OFFLINE_WINDOWS_ROOT for the licensing side. /cishim and /slshim have no build boundary; restore and read-only commands retain their existing scope.

For example, with a manually mounted newer preview:

~~~bat
nttimebomb.cmd /image D:\Mount
nttimebomb.cmd /cishim D:\Mount
dism /Unmount-Image /MountDir:D:\Mount /Commit
~~~

/cishim itself accepts a mounted directory or offline partition, not a WIM or ISO filename. When using a WIM or ISO workflow, mount or deploy the resulting Windows image and run /cishim before the final commit/repack.

## Standard SPP replacement

/spp requires user-supplied native spp* files, an spp tree, and selected CatRoot certificates or catalogs. Accepted layouts include flat exports, System32, and Windows\System32. A donor SysWOW64 directory supplies x86 components for an x64 target.

~~~bat
nttimebomb.cmd /image D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /spp D:\RTM-SPP /target D:\Mount
~~~

SPP files receive TrustedInstaller ownership, with the existing sppsvc access rules for sppsvc.exe and spp\store\2.0. Existing CatRoot owners and ACLs are retained. Selected catalogs supplied beside sppsvc.exe go to System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}. A donor CatRoot tree preserves relative paths. A supplied SKU catalog may retire the same SKU identity's old catalog whose version matches the target kernel.

Standard migration skips sppnp.dll, sppinst.dll, sppcomapi.dll, sppcommdlg.dll, and csvlk-pack-Volume-CSVLK-{2,3,4}-ul-store-rtm.xrm-ms under spp\tokens\skus\csvlk-pack. NT6 mode copies its supplied tokens independently of these exclusions.

### SPP-only replacement below Build 15063

Use /spponly when you want only the standard SPP replacement described above on an image below Build 15063. /spp identifies your donor; the value after /spponly identifies the offline Windows root or input WIM. A donor is required below that boundary. The equivalent /image ROOT /spponly form is also accepted. On Build 15063 or newer this mode refuses without changing anything and points at /cishim and /slshim.

~~~bat
nttimebomb.cmd /spponly D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /image D:\Mount /spponly /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\install.wim /out D:\install-spp.wim /index all /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\install.wim /out D:\edition-spp.wim /index 2 /spp D:\RTM-SPP
~~~

Below Build 15063, these commands replace the supplied native SPP files, optional SysWOW64 SPP files, the spp tree, and selected CatRoot files with the same exclusions, permissions, and catalog-retirement rules as standard SPP mode. They preserve boot files, CI, kernels, hvloader, WinRE, and LicensingUI.exe. When you supply an already mounted directory, commit it yourself afterward. When you supply a WIM, the tool stages a private copy and publishes /out only after all selected indexes succeed. The policy is evaluated separately for each index. Omit /index to select index 1.

For an installation ISO, the syntax is different: /media identifies the source, and the folder immediately after /spponly is the donor.

~~~bat
nttimebomb.cmd /media D:\Preview.iso /work D:\SPP-Work /out D:\Preview-spp.iso /spponly D:\RTM-SPP /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe
~~~

### Standard SPP donor for a multi-index WIM

When the input WIM contains more than one index, standard /spp and /spponly use shared binaries and separate SKU trees. This also applies when /index N selects just one index from that multi-index file. The same rule applies to multi-index install.wim processed by /media. Single-index WIMs and already mounted Windows roots keep the original donor layout, with spp and CatRoot at the native donor level. /spp-reference, restore, and /nt6 retain their existing layouts.

For example:

~~~text
D:\RTM-SPP\
  sppsvc.exe                 shared native spp* program files
  sppc.dll
  ...
  SysWOW64\                  shared x86 spp* program files for an x64 target
    sppc.dll
    ...
  Professional\              exact EditionID, case insensitive
    spp\
      tokens\...
      ...
    Professional-package.cat
  Enterprise\
    spp\...
    Enterprise-package.cat
~~~

The tool reads EditionID from each mounted index's offline SOFTWARE hive, closes the hive, and prints the selected SKU folder. Use EditionID names such as Professional, Enterprise, Core, ServerStandard, or ServerDatacenter, rather than a localized display name or index number. You can inspect an index's Edition with DISM before preparing the donor:

~~~bat
dism /English /Get-WimInfo /WimFile:D:\install.wim /Index:1
nttimebomb.cmd /spponly D:\install.wim /out D:\install-spp.wim /index all /spp D:\RTM-SPP
~~~

Keep native binaries at the common donor level (flat, System32, or Windows\System32 layouts are accepted), with common SysWOW64 binaries in the existing supported location. Keep each SKU directory directly under the directory passed to /spp. Place that SKU's spp folder and catalog files side by side, for example Enterprise\spp and Enterprise\package.cat. No CatRoot subfolder is required: these flat catalogs go to target Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}. An optional SKU\CatRoot tree remains supported and preserves its relative paths; supply each catalog only once. Shared-level spp trees, SysWOW64\spp trees, and shared-level catalogs are ignored in this multi-index mode, so they cannot mix licensing data between SKUs. A missing or unreadable EditionID, missing SKU directory, empty usable SPP tree, or missing usable catalogs stops the operation. No other SKU is used as a fallback, and a failed WIM operation does not publish /out.

Native/x86 architecture checks, the SPP exclusions listed above, permission handling, old matching SKU catalog retirement, and rollback still apply. Supply shared program files matching the target architecture; shared binaries do not make a mixed x86/x64 WIM compatible with one donor set.

## Reference migration and file restore

/spp-reference copies selected differing components and static licenses from a reference image of the same build, architecture, and edition. It preserves CatRoot and the activation store. /spp-restore restores the corresponding scope from an original image. Target-only files remain. Add /file to restore a single original file to an image-relative path.

For a mounted original image, pass its mount root as the donor. The tool finds
`Windows\System32` and the applicable `Windows\SysWOW64` files directly, so no
manual extraction is needed for this restore. Use a separate target mount.

~~~bat
nttimebomb.cmd /spp-reference D:\Reference /target D:\Mount
nttimebomb.cmd /spp-restore D:\Original /target D:\Mount
nttimebomb.cmd /spp-restore D:\Original\Windows\SysWOW64\sppwmi.dll /target D:\Mount /file Windows\SysWOW64\sppwmi.dll
~~~

Restored files receive original contents, owner, primary group, DACL, inheritance protection, and last-write time. Restore mode retains existing directory permissions.

## Standalone boot.wim and WinRE

/bootwim accepts an extracted image or a WIM. WIM input defaults to all indexes. /index selects one. WinRE also has its dedicated command.

~~~bat
nttimebomb.cmd /bootwim D:\BootMount
nttimebomb.cmd /bootwim D:\boot.wim /out D:\boot-patched.wim
nttimebomb.cmd patch-winre D:\Winre.wim D:\Winre-patched.wim
~~~

## Boot diagnostics and deployment notes

check-boot reads both Windows\System32\winload.efi and Windows\System32\Boot\winload.efi, the image boot manager, and the supplied ESP's EFI files. It prints versions, on-disk SHA-256 hashes, and in-memory patch-rule recognition results. No inspected files are modified.

~~~bat
nttimebomb.cmd check-boot W:\ S:\
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum all /v
~~~

VHDX native boot uses the physical machine's active EFI manager. Patching files inside a VHDX does not establish which manager firmware selects. Check the active firmware path, ESP contents, and BCD entry for 0xc0000428. Matching patch rules alone do not prove that firmware loaded that file.

For VMware tests of Server 2016 TP5, set the target entry's hypervisorlaunchtype to Off. Setup can re-enable it. Confirm the target identifier before editing a multiboot system.

~~~bat
bcdedit /store S:\EFI\Microsoft\Boot\BCD /enum {default}
bcdedit /store S:\EFI\Microsoft\Boot\BCD /set {default} hypervisorlaunchtype Off
~~~

PowerShell users must quote identifiers such as '{default}'. Secure Boot must permit the chosen boot chain. End-to-end firmware behavior requires testing on the destination hardware.

## Build from source

Use Zig 0.15.2 or newer (verified with 0.17.1) and Python 3 from the repository root. Python is needed only to
build the SLShim payloads, not to run the packaged tool. Fetch the pinned
Microsoft libraries, build the payloads and generated fingerprints, then compile
the main executables and MMC helpers for each architecture. Rebuild the main
executables whenever payloads change.
The core program has no PowerShell dependency. Only the applicable modes invoke
DISM, 7-Zip, or OSCDIMG.

~~~bat
python tools/fetch-offreg.py
python tools/build-slshim.py C:\Tools\zig\zig.exe
zig rc /fo as-invoker.res -- src/flightpatch.rc
zig cc -target x86-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-x86.exe
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-x64.exe
zig cc -target aarch64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -lcrypt32 -lncrypt -o nttimebomb-arm64.exe
zig cc -target x86-windows-gnu -municode -std=c11 -Oz -s src/mmc.c as-invoker.res -ladvapi32 -lbcrypt -lwintrust -lcrypt32 -lncrypt -o nttimebomb-mmc-x86.exe
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/mmc.c as-invoker.res -ladvapi32 -lbcrypt -lwintrust -lcrypt32 -lncrypt -o nttimebomb-mmc-x64.exe
zig cc -target aarch64-windows-gnu -municode -std=c11 -Oz -s src/mmc.c as-invoker.res -ladvapi32 -lbcrypt -lwintrust -lcrypt32 -lncrypt -o nttimebomb-mmc-arm64.exe
python tools/package.py D:\Output\nt-timebomb-patch-v5.3.0-winpe.zip
~~~

Maintainers extending the interface profiles can run
`python tools/inspect-slshim-abi.py D:\5483 D:\6946 D:\8032 D:\9431` on original
extracted native and SysWOW64 DLL sets. Existing profiles are retained while
the supplied profiles are updated. This optional inspection requires `pefile`
and `capstone`; it checks exports and regenerates the ABI facts/stubs. Named
interfaces reuse maintained calling-convention contracts. Protected older code
contains RET-based local jumps and inline data, so scanning arbitrary RET
instructions does not establish parameter counts. New ordinal interfaces need
verified return conventions; unknown widths stop generation. Adding an export
to a definition does not implement its behavior. The payload builder and packager
enumerate the committed profiles automatically. Rebuild payloads and both
executables afterward.

Exit codes are 0 for success, 1 for operation failure, 2 for invalid arguments, and 3 for missing required privileges. Preserve any reported remaining mount or backup paths when reporting a failure.

