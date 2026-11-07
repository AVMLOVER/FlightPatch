"""Build the independent shim and ABI-preserving forwarder DLLs. Python stdlib only."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import subprocess
import struct
import sys
import shutil
import tempfile

root=Path(__file__).resolve().parents[1]
zig=sys.argv[1] if len(sys.argv)>1 else os.environ.get('ZIG','zig')
zig_path=Path(shutil.which(zig) or zig).resolve()
windows_headers=zig_path.parent/'lib/libc/include/any-windows-any'
output=root/'slshim'
metadata=json.loads((root/'src/slshim_abi.json').read_text())
targets={'x86':'x86-windows-gnu','x64':'x86_64-windows-gnu','arm64':'aarch64-windows-gnu'}
arm_profile='29698'
def command(arguments):
    result=subprocess.run([zig,'cc',*arguments],cwd=root,capture_output=True,text=True)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
def build_runtime(arch):
    directory=output/arch
    directory.mkdir(parents=True,exist_ok=True)
    target=targets[arch]
    runtime_entry='DllMain@12' if arch=='x86' else 'DllMain'
    command(['-target',target,'-shared','-std=c11','-Oz','-s','-nostdlib',
             '-ffreestanding','-fno-builtin','-fno-stack-protector',
             '-isystem',str(windows_headers),
             '-Wl,--entry,'+runtime_entry,'src/slshim_runtime.c',
             'src/slshim_runtime.def','-ladvapi32','-lkernel32','-o',str(directory/'nttp-slshim.dll')])
    return directory

def build(arch):
    directory=build_runtime(arch)
    target=targets[arch]
    for profile,modules in metadata['profiles'].items():
        folder=directory/profile
        folder.mkdir(exist_ok=True)
        for module,exports in modules.items():
            definitions=['LIBRARY '+module+'.dll','EXPORTS']
            for entry in exports:
                name=entry['name'] or entry['core_name']
                definitions.append(f'  {name}=nttp-slshim.{entry["core_name"]} @{entry["ordinal"]}'+(' NONAME' if entry['name'] is None else ''))
            definition=root/'src/slshim_forwarders'/profile/(module+'.def')
            definition.parent.mkdir(parents=True,exist_ok=True)
            definition.write_text('\n'.join(definitions)+'\n')
            entry='sl_forwarder_entry@12' if arch=='x86' else 'sl_forwarder_entry'
            command(['-target',target,'-shared','-nostdlib','-Wl,--entry,'+entry,'-s','src/slshim_forwarder.c',str(definition),'-o',str(folder/(module+'.dll'))])
            # The MinGW x86 linker decorates the forwarder module name with
            # a C underscore. Normalize the string in place, keeping its RVA.
            path=folder/(module+'.dll')
            data=bytearray(path.read_bytes())
            prefix=b'_nttp-slshim.'
            position=0
            while (position:=data.find(prefix,position))>=0:
                end=data.index(0,position)
                data[position:end]=data[position+1:end]+b'\0'
                position=end+1
            pe=struct.unpack_from('<I',data,0x3c)[0]
            checksum=pe+0x58
            data[checksum:checksum+4]=b'\0'*4
            total=0
            for offset in range(0,len(data),2):
                total+=data[offset]+((data[offset+1]<<8) if offset+1<len(data) else 0)
                total=(total&65535)+(total>>16)
            total=((total&65535)+(total>>16))+len(data)
            struct.pack_into('<I',data,checksum,total)
            path.write_bytes(data)
    return arch
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    for arch in pool.map(build,['x86','x64']): print('Built',arch)

directory=build_runtime('arm64')
shutil.copyfile(output/'x64/nttp-slshim.dll',directory/'nttp-slshim-x64.dll')
folder=directory/arm_profile
folder.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='nttp-arm64x-') as temporary:
    work=Path(temporary)
    for arch in ('arm64','x64'):
        command(['-target',targets[arch],'-c','-nostdlib','-ffreestanding',
                 '-isystem',str(windows_headers),'src/slshim_arm64x.c','-o',str(work/(arch+'.obj'))])
    for module in metadata['profiles'][arm_profile]:
        native=root/'src/slshim_forwarders'/arm_profile/(module+'.def')
        emulated=work/(module+'.def')
        emulated.write_text(native.read_text().replace('nttp-slshim.','nttp-slshim-x64.'))
        result=subprocess.run([zig,'lld-link','/dll','/noentry','/machine:arm64x',
            '/defarm64native:'+str(native),'/def:'+str(emulated),
            str(work/'arm64.obj'),str(work/'x64.obj'),'/out:'+str(folder/(module+'.dll'))],
            cwd=root,capture_output=True,text=True)
        if result.returncode or 'missing' in result.stderr:
            raise RuntimeError(result.stdout+result.stderr)
print('Built arm64 and ARM64X forwarders')

header=['/* Generated payload fingerprints and original ABI facts. */',
        'typedef struct { const wchar_t *relative; const char *sha; } SlPayload;',
        'typedef struct { const char *name; WORD ordinal; } SlExport;',
        'typedef struct { WORD machine; const wchar_t *module; const wchar_t *profile; const SlExport *exports; unsigned count; SlPayload payload; } SlLibrary;']
records=[]
for profile,modules in metadata['profiles'].items():
    for module,exports in modules.items():
        symbol=f'sl_exports_{profile}_{module}'
        header.append(f'static const SlExport {symbol}[] = {{')
        for entry in exports:
            name=json.dumps(entry['name']) if entry['name'] else 'NULL'
            header.append(f'  {{{name}, {entry["ordinal"]}}},')
        header.append('};')
        for arch,machine in [('x86','14c'),('x64','8664'),('arm64','aa64')]:
            path=output/arch/profile/(module+'.dll')
            if arch=='arm64' and profile!=arm_profile: continue
            sha=hashlib.sha256(path.read_bytes()).hexdigest()
            relative=str(path.relative_to(root)).replace('\\','/')
            records.append(f'  {{0x{machine}, L"{module}.dll", L"{profile}", {symbol}, {len(exports)}, {{L"{relative}", "{sha}"}}}},')
header+=['static const SlLibrary sl_libraries[] = {',*records,'};', 'static const SlPayload sl_runtime_payloads[] = {']
for arch in ['x86','x64','arm64']:
    path=output/arch/'nttp-slshim.dll'
    header.append(f'  {{L"slshim/{arch}/nttp-slshim.dll", "{hashlib.sha256(path.read_bytes()).hexdigest()}"}},')
path=output/'arm64/nttp-slshim-x64.dll'
header+=['};',f'static const SlPayload sl_woa_emulated = {{L"slshim/arm64/nttp-slshim-x64.dll", "{hashlib.sha256(path.read_bytes()).hexdigest()}"}};',
    'static const SlPayload sl_offreg_payloads[] = {',
    ' {L"dependencies/offreg-x86.dll", "da796eece1555a506dd9639dcbaa97d269dccff418e2901bdc633b9f99609e22"},',
    ' {L"dependencies/offreg-x64.dll", "11d89ec186dc27b220bc573b3d4686dedf8cf1d571af33bbbb0ce89b771ef362"},',
    ' {L"dependencies/offreg-arm64.dll", "059d6eb0e9a406eaf69cad82719c3ae4e270ba5d5ec5ee834fade7340438252e"},','};']
(root/'src/slshim_payloads.h').write_text('\n'.join(header)+'\n')
