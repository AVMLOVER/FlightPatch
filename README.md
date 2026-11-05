# NT Timebomb Patch 5.1

Version 5.1 adds support for the x86 image-hash routine used by the supplied Windows 10 build 10587 Legacy memtest.exe. Its FlightSigned OID reference is loaded into ECX. Existing caller, branch, and unique-match checks still apply.

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

NT6 mode does not replace SPP binaries, CatRoot, the store database, or SysWOW64. It does not patch CI, boot managers, loaders, or kernels, and never renames LicensingUI, regardless of the target build. Supply tokens appropriate for your target. Files are staged and verified before publication. On failure the tool attempts to restore original files and directory permissions.

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

Both combinations service every install.wim index and rebuild the ISO. /spponly uses standard SPP replacement, including its SysWOW64 handling, CatRoot rules and exclusions. /nt6 copies System32 SPP tokens with SPPSVC access and automatically applies optional Branding with TrustedInstaller access. Both preserve boot.wim, root boot managers, CI, loaders, kernels and LicensingUI. These explicit media replacement modes bypass the Build 15058 popup policy. The original /media /spp combination still performs the full boot-patching workflow.

The tool performs the following operations.

1. Extract the ISO with 7-Zip, or copy the media tree to the private workspace.
2. Mount, service, and commit every boot.wim index.
3. Mount, service, and commit every install.wim index.
4. Patch root Legacy bootmgr and UEFI bootmgr.efi for supported older media.
5. Build a dual BIOS/UEFI UDF ISO with OSCDIMG using the original El Torito boot images.

For older images, the normal offline workflow also handles existing Windows boot managers, loaders, CI, hvloader, and WinRE. Main-system and WinRE kernels remain unchanged. Optional /spp D:\RTM-SPP replaces SPP in every install.wim index, but does not apply the donor to boot.wim. Use a donor appropriate for every installation edition and architecture being processed, or service selected images separately.

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

WIM input requires a new /out path. /image defaults to index 1. Use /media for all installation indexes. Supported earlier files are identified using PE structure and code patterns. The existing matcher does not require a build number or PDB.

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

For /image, standalone /spponly, /bootwim, and the full-patching /media workflow, Build 15058 or newer uses a separate policy. Only Windows\System32\LicensingUI.exe is renamed to LicensingUI.exe.bak, when present. Existing backups are preserved. Newer media-root boot managers are retained. This addresses the popup. The watermark remains, and MMC or Windows Defender can still be affected after expiration. NT6 and the two replacement-only media modes operate independently of this policy.

## Standard SPP replacement

/spp requires user-supplied native spp* files, an spp tree, and selected CatRoot certificates or catalogs. Accepted layouts include flat exports, System32, and Windows\System32. A donor SysWOW64 directory supplies x86 components for an x64 target.

~~~bat
nttimebomb.cmd /image D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /spponly D:\Mount /spp D:\RTM-SPP
nttimebomb.cmd /spp D:\RTM-SPP /target D:\Mount
~~~

SPP files receive TrustedInstaller ownership, with the existing sppsvc access rules for sppsvc.exe and spp\store\2.0. Existing CatRoot owners and ACLs are retained. Selected catalogs supplied beside sppsvc.exe go to System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}. A donor CatRoot tree preserves relative paths. A supplied SKU catalog may retire the same SKU identity's old catalog whose version matches the target kernel.

Standard migration skips sppnp.dll, sppinst.dll, sppcomapi.dll, sppcommdlg.dll, and csvlk-pack-Volume-CSVLK-{2,3,4}-ul-store-rtm.xrm-ms under spp\tokens\skus\csvlk-pack. NT6 mode copies its supplied tokens independently of these exclusions.

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

Use Zig 0.15.2 from the repository root. The core program has no PowerShell dependency. Only the applicable modes invoke DISM, 7-Zip, or OSCDIMG.

~~~bat
zig rc /fo as-invoker.res -- src/flightpatch.rc
zig cc -target x86-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o nttimebomb-x86.exe
zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c as-invoker.res -ladvapi32 -lbcrypt -lntdll -lversion -o nttimebomb-x64.exe
~~~

Exit codes are 0 for success, 1 for operation failure, 2 for invalid arguments, and 3 for missing required privileges. Preserve any reported remaining mount or backup paths when reporting a failure.
