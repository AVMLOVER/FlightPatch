# 5.2 validation

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

No target-system boot, expired MMC, or expired Defender execution test was possible here. Those outcomes remain to be tested in the destination VM or computer. Native x86 newer-preview and ARM64 expiry callbacks are not verified. The archive contains no Windows samples, patched Windows binaries, PDBs, or QA helper executables.

## Experimental SLShim validation

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

Both supplied ProductPolicy blobs have no expiration entry. Their original SKU
feature policy is retained; absence of that entry does not prove absence of
other preview expiry checks. `/cishim` is independent. The shim's dedicated
LocalSystem service is configured offline but has not been started in a booted
target system here. OOBE, sign-in, service startup, MMC/Defender expiry behavior,
and third-party consumers of unsupported licensing APIs still need destination
VM testing. The package is an experimental build, not a claim of universal
Windows build compatibility or Microsoft activation.
