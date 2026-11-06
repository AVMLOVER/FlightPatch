# Offline Registry Library

Only `/slshim` and `/slshim-restore` load these Microsoft DLLs. Ordinary patching
does not load them. Both host architectures are included in the complete binary
ZIP. Keep this directory beside the executables. Windows 10 / WinPE 10 or newer
is the supported servicing environment for this mode. The target is offline.

The binaries are unmodified downloads from Microsoft's symbol server. They are
not licensing DLLs from the supplied Windows samples. SHA-256 fingerprints are
pinned by the installer and the download script. Microsoft identifies this library
as a binary redistributable DLL in its documentation linked below. Microsoft terms
apply separately from the project's GPL license; see the accompanying notice.

| Package name | File version | SHA-256 |
| --- | --- | --- |
| offreg-x86.dll | 10.0.19040.1 | da796eece1555a506dd9639dcbaa97d269dccff418e2901bdc633b9f99609e22 |
| offreg-x64.dll | 10.0.19041.1 | 11d89ec186dc27b220bc573b3d4686dedf8cf1d571af33bbbb0ce89b771ef362 |

Sources: [Microsoft x86 binary](https://msdl.microsoft.com/download/symbols/offreg.dll/39F397A413000/offreg.dll),
[Microsoft x64 binary](https://msdl.microsoft.com/download/symbols/offreg.dll/0A2A462F1b000/offreg.dll).
The x86 symbol identity corresponds to the 19041 baseline, but its downloaded
file resource reports 19040.1; the table reflects the actual file.

For a source checkout, run `python tools/fetch-offreg.py` to obtain the matching
files. It verifies both downloads before publishing either destination. No ADK
installation is needed for these two libraries.

API documentation: [Microsoft Offline Registry Library](https://learn.microsoft.com/en-us/windows/win32/devnotes/offline-registry-library-portal).
The tool opens hives through this library and saves new staged files; it does
not mount the target hives into the running computer's registry.
