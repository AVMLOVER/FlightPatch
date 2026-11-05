# NT Timebomb Patch 5.0

NT Timebomb Patch is an offline command-line tool for Windows prerelease images. It replaces NT6 licensing tokens, services older FlightSigned boot files, processes installation media, and rebuilds BIOS/UEFI ISOs with Microsoft OSCDIMG. The former FlightPatch command name remains available as a compatibility launcher.

## Requirements and permissions

Extract the complete ZIP. Run nttimebomb.cmd from an elevated Command Prompt on Windows, or a LocalSystem command prompt in Windows PE. The launcher selects the x86 or x64 executable for the current environment. The target architecture is detected separately. Use local drive paths shorter than MAX_PATH and quote paths containing spaces.

For protected files, open a new privileged prompt with NSudo, change to the tool directory, and run the command there. Administrator elevation with backup and restore privileges is normally sufficient on Windows. In WinPE, use SYSTEM.

~~~bat
NSudoLC.exe -U:S -P:E cmd.exe
NSudoLC.exe -U:T -P:E cmd.exe
nttimebomb.cmd /help
~~~

WIM servicing uses Windows DISM. ISO creation requires OSCDIMG from the Microsoft Windows ADK. ISO input additionally requires 7z.exe and its runtime files from 7-Zip. Place dependencies beside the executable, add them to PATH, or specify /oscdimg and /7zip. Only ISO extraction requires 7-Zip. Only ISO creation requires OSCDIMG.

## NT6 tokens-only replacement

Use /nt6 when only the SPP tokens tree should be replaced. /file identifies the donor folder. /target identifies an offline Windows root containing Windows\System32\Config\SYSTEM.

~~~bat
nttimebomb.cmd /nt6 /file D:\Donor /target W:\
flightpatch.cmd /nt6 /file "D:\Donor\Windows\System32\spp\tokens" /target D:\Mount
~~~

The donor may contain Windows\System32\spp\tokens, System32\spp\tokens, spp\tokens, or tokens. You may also point directly to a directory named tokens. Supply one unambiguous tokens tree. A complete donor image is accepted, but only its System32 SPP tokens are copied.

This mode writes only inside the target Windows\System32\spp\tokens. Matching files are replaced. Target-only tokens remain. NT SERVICE\sppsvc receives Full Control on the tokens directory, every subdirectory, and every file, including target-only items. Other existing access rules and target owners are retained. The grant applies to the tokens tree.

NT6 mode does not replace SPP binaries, CatRoot, the store database, or SysWOW64. It does not patch CI, boot managers, loaders, or kernels, and never renames LicensingUI, regardless of the target build. Supply tokens appropriate for your target. Files are staged and verified before publication. On failure the tool attempts to restore original files and directory permissions.

## Complete installation media to a new ISO

/media accepts a Windows installation ISO or its extracted directory. This is different from a mounted Windows image. The source must contain root bootmgr and bootmgr.efi, sources\boot.wim, sources\install.wim, boot\etfsboot.com, and efi\microsoft\boot\efisys.bin.

~~~bat
nttimebomb.cmd /media D:\Preview.iso /work D:\NTTP-Work /out D:\Preview-patched.iso /oscdimg C:\Tools\oscdimg.exe /7zip C:\Tools\7z.exe
nttimebomb.cmd /media D:\ExtractedDVD /work D:\NTTP-Work2 /out D:\Preview-patched2.iso /oscdimg C:\Tools\oscdimg.exe
~~~

Both /work and /out must be new paths. Keep them outside the source directory, and keep the output outside the workspace. The source is preserved. Allow enough local NTFS space for the media copy, DISM staging, and output ISO.

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

### Build 15058 and newer

For /image, /spponly, /bootwim, and WIM images inside /media, Build 15058 or newer uses a separate policy. Only Windows\System32\LicensingUI.exe is renamed to LicensingUI.exe.bak, when present. Existing backups are preserved. Newer media-root boot managers are retained. This addresses the popup. The watermark remains, and MMC or Windows Defender can still be affected after expiration. NT6 tokens-only is independent of this policy.

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
