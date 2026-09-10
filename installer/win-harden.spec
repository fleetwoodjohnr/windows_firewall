# One COLLECT owns all runtime files, so independent bundles cannot overwrite
# each other's DLLs. GUI-only modules are excluded from privileged executables.
from pathlib import Path
root = Path(SPECPATH).parent
common = [(str(root / 'scripts' / 'ps'), 'scripts/ps'),
          (str(root / 'scanner' / 'ps'), 'scanner/ps')]
hidden = ['win32timezone', 'win32api', 'win32security', 'win32pipe', 'win32file',
          'win32event', 'win32job', 'win32ts', 'win32service', 'win32serviceutil', 'servicemanager', 'pywintypes']
gui = Analysis([str(root / 'win-harden.py')], pathex=[str(root)],
    datas=common + [(str(root / 'win_harden' / 'style.qss'), 'win_harden')],
    hiddenimports=hidden + ['broker.actions.' + p for p in
        ('defender','exploit','exposure','credential','dns','tls','system_state')] + ['win_harden.pages.' + p for p in
        ('dashboard','firewall','networks','protection','hardening','virus_scan')],
    excludes=[])
broker = Analysis([str(root / 'win-harden-broker.py')], pathex=[str(root)], datas=common,
    hiddenimports=hidden + ['broker.actions.' + p for p in
        ('defender','exploit','exposure','credential','dns','tls','system_state')], excludes=['PySide6'])
service = Analysis([str(root / 'win-harden-scanner.py')], pathex=[str(root)], datas=common,
    hiddenimports=hidden + ['broker.actions.' + p for p in
        ('defender','exploit','exposure','credential','dns','tls','system_state')], excludes=['PySide6'])
app_exe = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name='win-harden',
    console=False, icon=str(root / 'build' / 'win-harden.ico'), manifest=str(root / 'installer' / 'app.manifest'))
broker_exe = EXE(PYZ(broker.pure), broker.scripts, [], exclude_binaries=True, name='win-harden-broker',
    console=True, manifest=str(root / 'installer' / 'broker.manifest'))
service_exe = EXE(PYZ(service.pure), service.scripts, [], exclude_binaries=True, name='win-harden-scanner',
    console=True, manifest=str(root / 'installer' / 'app.manifest'))
coll = COLLECT(app_exe, broker_exe, service_exe, gui.binaries, gui.datas,
    broker.binaries, broker.datas, service.binaries, service.datas, name='win-harden')
