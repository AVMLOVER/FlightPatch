"""Package built executables, own payloads, notices and source, excluding samples."""
from pathlib import Path
import hashlib
import re
import sys
import zipfile

root=Path(__file__).resolve().parents[1]
if len(sys.argv)!=2:raise SystemExit('Usage: python tools/package.py OUTPUT.zip')
destination=Path(sys.argv[1]).resolve()
if destination.suffix.lower()!='.zip':raise SystemExit('Use a .zip output filename')
files={}
def include(path):
    if not path.is_file():raise SystemExit('Missing package file: '+str(path))
    files[path.relative_to(root).as_posix()]=path.read_bytes()

for name in ['nttimebomb-x86.exe','nttimebomb-x64.exe','nttimebomb.cmd','flightpatch.cmd',
             'README.md','TESTING.md','LICENSE']:
    include(root/name)
for folder in ['src','tools']:
    for path in sorted((root/folder).rglob('*')):
        if path.is_file() and path.suffix.lower() in ['.c','.h','.rc','.manifest','.def','.json','.py']:
            include(path)
for name in ['README.md','Microsoft-OFFREG-NOTICE.txt','offreg-x86.dll','offreg-x64.dll']:
    include(root/'dependencies'/name)
for arch in ['x86','x64']:
    include(root/'slshim'/arch/'nttp-slshim.dll')
    for profile in ['17746','29698']:
        for module in ['slc','slcext','sppc','sppcext','slwga']:
            include(root/'slshim'/arch/profile/(module+'.dll'))

fingerprints=re.findall(r'L"((?:slshim|dependencies)/[^\"]+)", "([0-9a-f]{64})"',
                       (root/'src/slshim_payloads.h').read_text())
if len(fingerprints)!=24:raise SystemExit('Unexpected payload fingerprint count')
for name,expected in fingerprints:
    if hashlib.sha256(files[name]).hexdigest()!=expected:
        raise SystemExit('Payload/header mismatch; rebuild payloads and both executables: '+name)
files['SHA256SUMS.txt']=''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                              for name,data in sorted(files.items())).encode('utf-8')
destination.parent.mkdir(parents=True,exist_ok=True)
temporary=destination.with_name(destination.name+'.pending')
try:
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        for name,data in sorted(files.items()):archive.writestr(name,data)
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip():raise SystemExit('ZIP CRC verification failed')
        if set(archive.namelist())!=files.keys():raise SystemExit('ZIP member mismatch')
        for name,data in files.items():
            if archive.read(name)!=data:raise SystemExit('ZIP content differs: '+name)
    temporary.replace(destination)
finally:
    temporary.unlink(missing_ok=True)
print(f'{destination}\n{len(files)} files; {destination.stat().st_size} bytes')
print('SHA-256 '+hashlib.sha256(destination.read_bytes()).hexdigest())
