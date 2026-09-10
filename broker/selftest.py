"""Non-mutating frozen-runtime check used by the build and Windows harness."""
import os
from pathlib import Path
import sys


def check(gui=False):
    if os.name != 'nt' or sys.getwindowsversion().build < 22000:
        raise RuntimeError('Windows 11 is required.')
    import win32api
    import win32security
    import win32file
    import win32pipe
    import win32service
    import win32job
    import win32ts
    import win32event
    import servicemanager
    from .psinvoke import script_dir, SCRIPTS
    from scanner.engine import PS_ROOT
    from .actions import load_families
    if len(load_families()) != 6:
        raise RuntimeError('One or more hardening backends were not bundled.')
    for path in [*(Path(script_dir()) / name for name in SCRIPTS), PS_ROOT / 'status.ps1', PS_ROOT / 'operation.ps1']:
        if not path.is_file():
            raise RuntimeError(f'Missing runtime resource: {path}')
    if gui:
        from win_harden.application import load_stylesheet
        from PySide6.QtWidgets import QApplication
        from win_harden.window import MainWindow, _PagePlaceholder
        from win_harden.settings import AppSettings
        import tempfile
        app = QApplication.instance() or QApplication([])
        if not load_stylesheet():
            raise RuntimeError('The stylesheet is missing.')
        with tempfile.TemporaryDirectory() as folder:
            window = MainWindow(settings=AppSettings(str(Path(folder) / 'settings.json')))
            try:
                if any(isinstance(page, _PagePlaceholder) for page in window.pages.values()):
                    raise RuntimeError('A page could not be constructed.')
            finally:
                window.shutdown()
    return 0
