"""Generate PyInstaller's Windows VERSIONINFO from the application version."""
from pathlib import Path
import runpy

ROOT = Path(__file__).resolve().parent.parent


def generate(version):
    parts = tuple(int(p) for p in version.split('.')) + (0,)
    return f'''VSVersionInfo(
  ffi=FixedFileInfo(filevers={parts!r}, prodvers={parts!r}, mask=0x3f,
    flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'jrf'),
    StringStruct('FileDescription', 'Windows Firewall & Hardening'),
    StringStruct('FileVersion', {version!r}),
    StringStruct('ProductName', 'Windows Firewall & Hardening'),
    StringStruct('ProductVersion', {version!r})
  ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])]
)
'''


if __name__ == '__main__':
    version = runpy.run_path(str(ROOT / 'win_harden' / 'version.py'))['VERSION']
    destination = ROOT / 'build' / 'version-info.txt'
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(generate(version), encoding='utf-8')
