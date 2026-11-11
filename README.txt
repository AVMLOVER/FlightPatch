NT Timebomb Patch 5.3.0 - updated build
=======================================

These executables are built from ..\src with the commands in the top-level
README ("Build from source"):

  zig rc /fo as-invoker.res -- src/flightpatch.rc
  zig cc -target x86_64-windows-gnu -municode -std=c11 -Oz -s src/flightpatch.c ...
  zig cc -target x86-windows-gnu ...
  zig cc -target aarch64-windows-gnu ...

Zig 0.17.1 was used. nttimebomb.cmd and flightpatch.cmd are copies of the
launchers so this folder works on its own.

New or extended commands:

  nttimebomb /cishim        OFFLINE_ROOT | FOLDER | FILE
  nttimebomb /cishim-boot   OFFLINE_ROOT | FOLDER | FILE
  nttimebomb /wintrust                      (running Windows, elevated)
  nttimebomb /wintrust-restore              (running Windows, elevated)
  nttimebomb /wintrust-approval OFFLINE_ROOT
  nttimebomb /wintrust-approval-restore OFFLINE_ROOT
  nttimebomb /winload-modify EFI_PARTITION [LEGACY_VOLUME_OR_WINDOWS_ROOT]
  nttimebomb /restore       OFFLINE_ROOT | FOLDER | FILE

/cishim now writes System32\ci.dll together with winload.efi, winresume.efi,
winload.exe and winresume.exe (and their System32\Boot hard links), so a UEFI
or legacy start keeps the nointegritychecks BCD option without pressing F8.
/wintrust and /wintrust-approval remove the certificate-period check from
wintrust.dll and crypt32.dll (System32 and SysWOW64) and sign the result with a
local certificate that is installed as a trusted root and publisher, because a
rewritten signed DLL is rejected at load otherwise. /wintrust works on the running
system and schedules the replacement for the next start; /wintrust-approval works
on an offline image and writes the certificate into its SOFTWARE hive.
nttimebomb-mmc-*.exe share the same signer. /winload-modify patches a release loader on an EFI
System Partition or a legacy volume so it accepts the modified image.

Every changed file keeps a verified FILE.bak beside it, and /restore puts the
original bytes and permissions back.

/restore, /cishim and /wintrust only need files; the licensing modes (/slshim)
also need the slshim\ and dependencies\ folders from the main package, so run
those from ..\ or copy those folders here.
