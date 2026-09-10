"""Run the actual frozen executables from outside the source tree."""
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='win-harden-smoke-') as cwd:
    for name in ('win-harden.exe', 'win-harden-broker.exe', 'win-harden-scanner.exe'):
        completed = subprocess.run([str(root / name), '--self-test'], cwd=cwd, timeout=120)
        if completed.returncode:
            raise SystemExit(f'{name} failed its frozen-runtime test ({completed.returncode})')
print('All three frozen executables passed their runtime checks.')
