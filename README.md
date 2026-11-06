# NT Timebomb Patch 5.2 (experimental)

Version 5.2 adds explicit /cishim servicing with no build-number check, based on the zero-expiry callback principle in cishim, and a separate experimental /slshim licensing-layer replacement with offline restore. It restores the Build 15058 boundary for ordinary image/SPP workflows: newer images only have LicensingUI.exe renamed and receive a prompt to use /cishim. The per-SKU SPP donor layout and the 10587 Legacy memtest.exe support are retained. This is an experimental preview release; destination-system boot and expiry behavior still need testing. Download the complete binary ZIP from the [5.2 release](https://github.com/AVMLOVER/FlightPatch/releases/tag/v5.2); GitHub's automatic source archives do not contain the built executables or DLL payloads.

NT Timebomb Patch is an offline command-line tool for Windows prerelease images. It replaces NT6 licensing tokens and optional Branding, services older FlightSigned boot files, processes installation media, and rebuilds BIOS/UEFI ISOs with Microsoft OSCDIMG. The former FlightPatch command name remains available as a compatibility launcher.

## Requirements and permissions

Extract the complete ZIP. Run nttimebomb.cmd from an elevated Command Prompt on Windows, or a LocalSystem command prompt in Windows PE. The launcher selects the x86 or x64 executable for the current environment. The target architecture is detected separately. Use local drive paths shorter than MAX_PATH and quote paths containing spaces.

For protected files, open a new privileged prompt with NSudo, change to the tool directory, and run the command there. Administrator elevation with backup and restore privileges is normally sufficient on Windows. In WinPE, use SYSTEM.

~~~bat
NSudoLC.exe -U:S -P:E cmd.exe
NSudoLC.exe -U:T -P:E cmd.exe
nttimebomb.cmd /help
~~~

WIM servicing uses Windows DISM. ISO creation requires OSCDIMG from the Microsoft Windows ADK. ISO input additionally requires 7z.exe and its runtime files from 7-Zip. Place dependencies beside the executable, add them to PATH, or specify /oscdimg and /7zip. Only ISO extraction requires 7-Zip. Only ISO creation requires OSCDIMG.

## Explicit CI build-expiry patch

Use /cishim with an already mounted or deployed offline Windows root. Supply the directory containing Windows, rather than the ci.dll filename or the Windows directory itself.

~~~bat
nttimebomb.cmd /cishim D:\Mount
nttimebomb.cmd /cishim W:\
~~~

This command processes only Windows\System32\ci.dll. It does not query the Windows build or require ntoskrnl.exe, SPP donors, PDBs, downloads, or a replacement shim at runtime. It leaves LicensingUI.exe, SPP, boot files, hvloader, WinRE, BCD, and kernels unchanged. Run /image first if you also want the normal newer-image LicensingUI rename, then run /cishim explicitly before committing your manually mounted image.

The expiry principle comes from [gailium119/cishim](https://github.com/gailium119/cishim/blob/c0ec25dbcb8e11109e24297c40d72c2ab6b24a8d/cishim/cishim.c): its CiGetBuildExpiryTime callback writes zero to the output and returns success. NT Timebomb Patch implements that behavior independently in the original CI. It identifies the preview's self-image expiry routine and confirms that CiInitialize registers it as a callback. The supplied preview 17746 and 29698 samples use different callback-table slots, both of which are checked structurally. An entry jump redirects to a small leaf routine in verified INT3 padding outside unwind-function ranges; the original unwind tables and other CI callbacks are retained. The full cishim module and its other signature-validation stubs are not bundled.

For these newer preview callbacks, the verified target architecture is x64. Both the x86 and x64 tool executables can process those x64 samples. Existing earlier x86/x64 FlightSigned CI matching remains available under /cishim. A newer native x86 or ARM64 expiry callback is not currently verified and is rejected if its layout is unsupported. No build-number gate does not mean that an unknown machine-code layout can be patched safely: missing anchors, ambiguous matches, or unavailable leaf space cause a failure before writing.

Before the first write, the tool saves ci.dll.nttp-original beside the target CI, verifying its contents and copying owner, group, DACL, inheritance protection, and last-write time. The original CI is then edited in place, retaining its ACL and restoring its read-only attribute. A write failure attempts to restore the original bytes. Existing backups are never overwritten; a conflicting backup stops the write. Re-running /cishim recognizes its existing patch and makes no further changes. Preserve the original backup for offline recovery.

The patch changes a signed system binary; it does not regenerate Microsoft's signature or configure Secure Boot, HVCI, BCD, or the selected boot manager. The target boot chain must accept the modified file. Verification with the supplied preview files checks structural matching, patch bytes, checksum, repeat behavior, permissions, and file scope. Booting an expired preview and confirming MMC/Defender behavior still requires testing in that target system; stock release CI is not evidence of preview-expiry removal.

## Experimental SLShim licensing-layer replacement

Use `/slshim` to install an independent replacement for the Windows licensing
client layer into a mounted or deployed **offline** Windows root. This is the
full replacement mode: it disables the target's SPP services and installs a
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
both executables. The tool selects target architecture separately from host
architecture, so the x86 executable can service an offline x64 image. Native
ARM64 targets are not supported by this mode.

The installer checks the original export names and ordinals before allowing a
replacement. The supplied 17746 and 29698 preview interfaces are covered for x64
and their x86 SysWOW64 companions. Matching is based on the DLL interface, rather
than a minimum or maximum Build check; an unverified interface is rejected.
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

The offline SYSTEM hive supplies that target SKU's ProductPolicy. The shim
preserves its feature policies, removes an exact `Kernel-ExpirationDate` entry
if present, and clears `Kernel-NonGenuineNotificationType` if present. The cache
is stored in the protected `SYSTEM\NTTimebombSLShim` key. Both supplied previews
have no expiration entry in ProductPolicy, so this step alone is not evidence
that CI build expiry has been removed. `/cishim` remains a separate command:

~~~bat
nttimebomb.cmd /cishim D:\Mount
nttimebomb.cmd /slshim D:\Mount
dism /Unmount-Image /MountDir:D:\Mount /Commit
~~~

The target's existing `sppsvc` and `sppuinotify` services are disabled. A dedicated
`NTTimebombSLShim` svchost group and service are created; the service maintains
the cached kernel policy after the target boots. It does not share the
DcomLaunch group and does not change Office's `osppsvc`. The local runtime
reports licensed/genuine status and answers policy queries from that SKU's
cache. Unknown policies return an error. Unsupported activation, ticket, COM,
and other private interfaces return an explicit unsupported result; this mode
does not issue a Microsoft digital license or implement online activation.

### SLShim backup and restore

Before target files are published, originals are copied to
`OFFLINE_ROOT\NTTimebombBackup\SLShim`. Keep that directory with the image.
It contains verified original DLLs and hives, original file metadata, and the
deployment manifest. Existing original backups are not overwritten. Repeating
an intact installation reports that it is already installed. An interrupted
prepared deployment can be restored with the same command shown below.

~~~bat
nttimebomb.cmd /slshim-restore D:\Mount
~~~

Restore puts back the original DLLs and removes the added runtime DLLs. It
restores the saved SPP service start settings and ProductPolicy, and removes
the shim service, cache, and svchost group. It edits the current offline hives
instead of copying an old complete hive over them, preserving unrelated registry
changes made since installation. The initial ProductPolicy snapshot itself is
restored. Unknown changed licensing DLLs or a changed OS edition/build stop
restore to avoid downgrading a serviced installation. Backups remain after a
successful restore. Archive the restored `SLShim` backup directory before a
fresh installation; the tool deliberately does not replace its original backup.

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

Below Build 15058, NT6 mode does not replace SPP binaries, CatRoot, the store database, or SysWOW64. It does not patch CI, boot managers, loaders, or kernels, and does not rename LicensingUI. Supply tokens appropriate for your target. Files are staged and verified before publication. On failure the tool attempts to restore original files and directory permissions. For a detected Build 15058 or newer, the normal newer-image policy applies instead: rename LicensingUI, skip tokens/Branding replacement, and suggest explicit /cishim.

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

Both combinations service every install.wim index and rebuild the ISO. Below Build 15058, /spponly uses standard SPP replacement, including its SysWOW64 handling, CatRoot rules and exclusions; /nt6 copies System32 SPP tokens with SPPSVC access and automatically applies optional Branding with TrustedInstaller access. Both preserve boot.wim, root boot managers, CI, loaders, and kernels. Build 15058 and newer indexes only have LicensingUI renamed and receive a /cishim suggestion; replacement is skipped in those indexes. The original /media /spp combination still performs the full older boot-patching workflow.

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

### Build 15058 and newer

For normal /image, /spponly, /spp, /spp-reference, /nt6, /bootwim, and /media image processing, Build 15058 or newer uses a separate policy. Only Windows\System32\LicensingUI.exe is renamed to LicensingUI.exe.bak, when present. Existing backups are preserved. SPP replacement and legacy boot patches are skipped, and the tool prompts you to run nttimebomb /cishim OFFLINE_ROOT explicitly on a mounted or deployed Windows image. Newer media-root boot managers are retained. The watermark remains. /cishim operates independently of the build boundary; restore and read-only commands retain their existing scope.

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

### SPP-only replacement below Build 15058

Use /spponly when you want only the standard SPP replacement described above on an image below Build 15058. /spp identifies your donor; the value after /spponly identifies the offline Windows root or input WIM. A donor is required below that boundary. The equivalent /image ROOT /spponly form is also accepted. On Build 15058 or newer, this mode follows the LicensingUI rename and /cishim suggestion policy instead of replacing SPP.

~~~bat
nttimebomb.cmd /spponly D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /image D:\Mount /spponly /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\install.wim /out D:\install-spp.wim /index all /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\install.wim /out D:\edition-spp.wim /index 2 /spp D:\RTM-SPP
~~~

Below Build 15058, these commands replace the supplied native SPP files, optional SysWOW64 SPP files, the spp tree, and selected CatRoot files with the same exclusions, permissions, and catalog-retirement rules as standard SPP mode. They preserve boot files, CI, kernels, hvloader, WinRE, and LicensingUI.exe. When you supply an already mounted directory, commit it yourself afterward. When you supply a WIM, the tool stages a private copy and publishes /out only after all selected indexes succeed. The policy is evaluated separately for each index. Omit /index to select index 1.

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

Use Zig 0.15.2 and Python 3 from the repository root. Python is needed only to
build the SLShim payloads, not to run the packaged tool. Fetch the pinned
Microsoft libraries, build the payloads and generated fingerprints, then compile
the two main executables. Rebuild both executables whenever payloads change.
The core program has no PowerShell dependency. Only the applicable modes invoke
DISM, 7-Zip, or OSCDIMG.

~~~bat
python tools/fetch-offreg.py
python tools/build-slshim.py C:\Tools\zig\zig.exe
zig rc /fo as-invoker.res -- src/flightpatch.rc
zig cc -target x86-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o nttimebomb-x86.exe
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o nttimebomb-x64.exe
python tools/package.py D:\Output\nt-timebomb-patch-v5.2-winpe.zip
~~~

Maintainers extending the interface profiles can run
`python tools/inspect-slshim-abi.py D:\17746 D:\29698` on original extracted
native and SysWOW64 DLL sets. That optional inspection requires `pefile` and
`capstone`; it verifies the original exports and x86 stack cleanup widths and
regenerates the committed ABI facts/stubs. Adding an export to a definition does
not implement its behavior. Rebuild payloads and both executables afterward.

Exit codes are 0 for success, 1 for operation failure, 2 for invalid arguments, and 3 for missing required privileges. Preserve any reported remaining mount or backup paths when reporting a failure.
