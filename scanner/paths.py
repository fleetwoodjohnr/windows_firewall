"""Windows paths resolved by the OS, and caller-access checks for scanning."""
import ctypes
import os
from pathlib import Path

from .protocol import local_path


def known_folder(folder_id):
    import uuid
    raw = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID(folder_id).bytes_le)
    result = ctypes.c_wchar_p()
    code = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(raw), 0, None, ctypes.byref(result))
    if code:
        raise OSError(code, "Windows could not locate the requested folder")
    try:
        return result.value
    finally:
        ctypes.windll.ole32.CoTaskMemFree(result)


def downloads_folder():
    return known_folder("374de290-123f-4565-9164-39c4925e467b")


def program_data():
    return known_folder("62ab5d82-fdc1-4dc3-a9dd-070d1d495d97")


def system_powershell():
    if os.name != "nt":
        return "powershell.exe"
    buf = ctypes.create_unicode_buffer(32768)
    if not ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf)):
        raise ctypes.WinError()
    return str(Path(buf.value) / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def check_access(path):
    """Call while impersonating the pipe client. Never follow reparse points.

    Defender receives a path, so this is an access boundary, not a promise that
    bytes cannot change later. The engine checks file identity before/after.
    """
    import win32file
    import win32con
    path = local_path(path)
    p = Path(path)
    for part in reversed([p, *p.parents]):
        attr = win32file.GetFileAttributes(str(part))
        if attr & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Reparse points and linked folders are not supported for custom scans.")
    handle = win32file.CreateFile(path, win32con.GENERIC_READ,
                                 win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                                 None, win32con.OPEN_EXISTING,
                                 win32con.FILE_FLAG_BACKUP_SEMANTICS | win32con.FILE_FLAG_OPEN_REPARSE_POINT, None)
    handle.Close()
    # Directory scans are expanded as the caller by the tray monitor. Do not
    # let SYSTEM recurse into files the requesting user cannot read.
    if p.is_dir():
        raise ValueError("Folder scans must submit their files individually.")
    return path


def protected_directory(path):
    """Create machine state with an explicit Windows DACL, never POSIX chmod."""
    import win32security
    import win32file
    path = Path(path)
    # Check ancestors before creating anything, including junctions (which
    # pathlib.is_symlink alone does not catch on Windows).
    for parent in reversed([path, *path.parents]):
        if parent.exists() and win32file.GetFileAttributes(str(parent)) & 0x400:
            raise ValueError("Refusing redirected machine state")
    if path.exists():
        descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                                                       win32security.OWNER_SECURITY_INFORMATION)
        owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        if owner not in ('S-1-5-18', 'S-1-5-32-544'):
            raise PermissionError("The machine state directory has an untrusted owner. Repair its ownership before continuing.")
    path.mkdir(parents=True, exist_ok=True)
    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;BU)", 1)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION |
        win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        sd.GetSecurityDescriptorOwner(), None, sd.GetSecurityDescriptorDacl(), None)
    return path
