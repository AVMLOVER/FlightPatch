"""Regenerate ABI facts from original user-supplied DLL sets; requires pefile/capstone.

Usage: python tools/inspect-slshim-abi.py D:\\5483 D:\\6946 D:\\8032 D:\\9431 D:\\17746 D:\\29698
Directories may be flat extractions or complete Windows roots. This inspection
is not required to build the committed, verified interface profiles.
"""
from pathlib import Path
import capstone,json,pefile,re,sys
source=Path(__file__).resolve().parents[1]/'src'
if len(sys.argv)<2:raise SystemExit(__doc__)
implemented={'SLOpen','SLClose','SLConsumeRight','SLGetLicensingStatusInformation','SLGetSLIDList',
 'SLGetPolicyInformation','SLGetPolicyInformationDWORD','SLGetApplicationInformation','SLGetPKeyInformation',
 'SLGetGenuineInformation','SLGetWindowsInformation','SLGetWindowsInformationDWORD','SLIsGenuineLocal',
 'SLIsGenuineLocalEx','SLIsWindowsGenuineLocal','SLInstallLicense',
 'SLLoadApplicationPolicies','SLUnloadApplicationPolicies'}
aliases={'SLGetProductSkuInformation':'SLGetPKeyInformation','SLGetServiceInformation':'SLGetPolicyInformation',
         'SLGetApplicationPolicy':'SLGetPolicyInformation','SLpGetGenuineLocal':'SLIsGenuineLocalEx',
         'SLGetGenuineInformationEx':'SLGetGenuineInformation'}
# These documented APIs have input parameters only. The local replacement has
# no activation/consumption transitions to persist or signal.
noops={'SLFireEvent','SLRegisterEvent','SLUnregisterEvent','SLPersistApplicationPolicies',
       'SLReArm','SLSetGenuineInformation','SLSetCurrentProductKey',
       'SLUninstallLicense','SLUninstallProofOfPurchase'}
dis=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);dis.detail=True
# Existing verified API contracts are authoritative for named interfaces.
# Protected older licensing binaries contain RET-based local jumps and embedded
# data after calls: a syntactic RET immediate is not necessarily an API return.
existing=json.loads((source/'slshim_abi.json').read_text())
contracts=existing['arity']
# Public SAM signatures from Microsoft's slpublic.h documentation:
# https://learn.microsoft.com/windows/win32/api/slpublic/nf-slpublic-slgetinstalledsamlicenseapplications
# https://learn.microsoft.com/windows/win32/api/slpublic/nf-slpublic-slgetsamlicense
# https://learn.microsoft.com/windows/win32/api/slpublic/nf-slpublic-slinstallsamlicense
# https://learn.microsoft.com/windows/win32/api/slpublic/nf-slpublic-sluninstallsamlicense
contracts.update({'SLGetInstalledSAMLicenseApplications':2,'SLGetSAMLicense':3,
                  'SLInstallSAMLicense':3,'SLUninstallSAMLicense':1})
arity=dict(contracts);profiles=dict(existing['profiles']);unknown=[];contract_fallback=set();seen_profiles=set()
def arguments(pe,rva):
    queue=[(rva,False)];seen=set();returns=set()
    while queue and len(seen)<2000:
        address,teardown=queue.pop()
        if address in seen:continue
        seen.add(address)
        try:raw=pe.get_offset_from_rva(address)
        except pefile.PEFormatError:continue
        instructions=list(dis.disasm(pe.__data__[raw:raw+15],address,count=1))
        if not instructions:continue
        i=instructions[0]
        if i.mnemonic.startswith('ret'):
            # Require a normal frame teardown, rather than a protected local
            # RET trampoline or disassembly through inline data.
            width=0 if not i.operands else i.operands[0].imm
            if i.mnemonic!='ret' or not teardown or width%4 or width>64:return None
            returns.add(width//4);continue
        if i.mnemonic in ['int3','ud2','hlt']:continue
        if i.mnemonic.startswith('j'):
            if i.operands and i.operands[0].type==capstone.x86.X86_OP_IMM:queue.append((i.operands[0].imm,False))
            if i.mnemonic=='jmp':continue
        teardown=i.mnemonic=='leave' or (i.mnemonic=='pop' and i.op_str=='ebp')
        queue.append((address+i.size,teardown))
    return next(iter(returns)) if len(returns)==1 else None
for argument in sys.argv[1:]:
    original=Path(argument).resolve()
    version=original.name
    if not re.fullmatch('[A-Za-z0-9_-]+',version) or version in seen_profiles:raise ValueError('Invalid/duplicate profile name')
    seen_profiles.add(version)
    native=next((original/p for p in ['Windows/System32','System32',''] if (original/p/'slc.dll').is_file()),None)
    wow=next((original/p for p in ['Windows/SysWOW64','SysWOW64'] if (original/p/'slc.dll').is_file()),None)
    if native is None:raise ValueError('Missing native DLL set: '+str(original))
    if wow is None:
        if pefile.PE(str(native/'slc.dll')).FILE_HEADER.Machine!=0x14c:raise ValueError('Provide the x86 companion DLLs')
        wow=native
    profile={}
    for module in ['slc','slcext','sppc','sppcext','slwga']:
        if not (native/(module+'.dll')).is_file() and not (wow/(module+'.dll')).is_file():continue
        pe=pefile.PE(str(wow/(module+'.dll')))
        if pe.FILE_HEADER.Machine!=0x14c:raise ValueError('Expected x86 code for argument-width inspection')
        native_pe=pefile.PE(str(native/(module+'.dll')))
        interface=lambda image:sorted((item.ordinal,item.name) for item in image.DIRECTORY_ENTRY_EXPORT.symbols)
        if interface(native_pe)!=interface(pe):raise ValueError('Native/x86 export interfaces differ: '+module)
        entries=[]
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name=export.name.decode() if export.name else f'nttp_ordinal_{module}_{export.ordinal}'
            count=arguments(pe,export.address) if not export.forwarder else None
            if name in contracts:
                if count!=contracts[name]:contract_fallback.add((version,module,name))
                count=contracts[name]
            if count is not None:
                if name in arity and arity[name]!=count:raise ValueError((name,arity[name],count))
                arity[name]=count
            entries.append({'name':export.name.decode() if export.name else None,'core_name':name,'ordinal':export.ordinal})
        profile[module]=entries
    profiles[version]=profile
all_names={e['core_name'] for p in profiles.values() for entries in p.values() for e in entries}
for name in all_names:
    if name not in arity:unknown.append(name)
if unknown:raise ValueError('Could not verify x86 arity: '+str(unknown))
metadata={'arity':dict(sorted(arity.items())),'profiles':profiles}
(source/'slshim_abi.json').write_text(json.dumps(metadata,indent=2)+'\n')
stubs=[];definitions=['LIBRARY nttp_slshim','EXPORTS','ServiceMain']
for count in sorted(set(arity.values())):
    if count>16:raise ValueError(count)
    parameters=','.join('void *a'+str(i) for i in range(count)) or 'void'
    discard=''.join('(void)a'+str(i)+';' for i in range(count))
    stubs.append(f'HRESULT WINAPI sl_unsupported{count}({parameters}) {{ {discard} return SL_UNSUPPORTED; }}')
    stubs.append(f'HRESULT WINAPI sl_success{count}({parameters}) {{ {discard} InitOnceExecuteOnce(&sl_once,sl_load,NULL,NULL); return sl_cache?S_OK:SL_MISSING; }}')
for name in sorted(all_names):
    target=name if name in implemented else aliases.get(name,('sl_success' if name in noops else 'sl_unsupported')+str(arity[name]))
    if target in aliases:target=aliases[target]
    if target in arity and arity[target]!=arity[name]:raise ValueError('Alias stack mismatch: '+name)
    definitions.append('    '+name+('='+target if target!=name else ''))
(source/'slshim_stubs.h').write_text('/* Generated verified x86 stdcall widths. See slshim_abi.json. */\n'+'\n'.join(stubs)+'\n')
(source/'slshim_runtime.def').write_text('\n'.join(definitions)+'\n')
print('Verified export interfaces',len(all_names),'arities',sorted(set(arity.values())))
print('Curated/documented ABI contracts used where code inspection was unavailable:',len(contract_fallback))
for name in sorted(implemented):print(name,arity.get(name))
