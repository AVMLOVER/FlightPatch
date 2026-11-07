"""Fetch unmodified, fingerprint-pinned Microsoft Offline Registry libraries."""
from pathlib import Path
import hashlib
import os
import urllib.request

root = Path(__file__).resolve().parents[1] / 'dependencies'
sources = [
    ('offreg-x86.dll', '39F397A413000', 'da796eece1555a506dd9639dcbaa97d269dccff418e2901bdc633b9f99609e22'),
    ('offreg-x64.dll', '0A2A462F1b000', '11d89ec186dc27b220bc573b3d4686dedf8cf1d571af33bbbb0ce89b771ef362'),
    ('offreg-arm64.dll', 'DA237CAC35000', '059d6eb0e9a406eaf69cad82719c3ae4e270ba5d5ec5ee834fade7340438252e'),
]
downloads = []
for name, identity, expected in sources:
    url = f'https://msdl.microsoft.com/download/symbols/offreg.dll/{identity}/offreg.dll'
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(2 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit(f'Fingerprint mismatch: {name}; no dependency files published.')
    downloads.append((name, data))
root.mkdir(exist_ok=True)
for name, data in downloads:
    temporary = root / (name + f'.download-{os.getpid()}')
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
        temporary.replace(root / name)
    finally:
        temporary.unlink(missing_ok=True)
    print(f'Verified {name}: {len(data)} bytes')
