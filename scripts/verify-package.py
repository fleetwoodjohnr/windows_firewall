"""Run the actual frozen executables from outside the source tree."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time

root = Path(sys.argv[1]).resolve()
cwd = Path(tempfile.mkdtemp(prefix='win-harden-smoke-'))
try:
    for name in ('win-harden.exe', 'win-harden-broker.exe', 'win-harden-scanner.exe'):
        completed = subprocess.run([str(root / name), '--self-test'], cwd=cwd, timeout=120)
        if completed.returncode:
            raise SystemExit(f'{name} failed its frozen-runtime test ({completed.returncode})')
finally:
    # Windows can retain a process working-directory handle briefly after the
    # process exits. Keep this bounded so a real orphan still fails the build.
    deadline = time.monotonic() + 10
    while True:
        try:
            cwd.rmdir()
            break
        except FileNotFoundError:
            break
        except PermissionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.25)
print('All three frozen executables passed their runtime checks.')
