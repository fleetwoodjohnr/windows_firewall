"""Release validation and bounded installer staging. No privileged operations."""

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import urlsplit

REPOSITORY = "fleetwoodjohnr/windows_firewall"
RELEASES_URL = f"https://github.com/{REPOSITORY}/releases"
LATEST_URL = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
MAX_INSTALLER = 1024 * 1024 * 1024
MAX_METADATA = 1024 * 1024
MAX_CHECKSUM = 4096
CHECK_INTERVAL = 24 * 60 * 60
# A failed attempt still stamps the attempt time, so retry sooner than the daily
# cadence rather than losing a day to a rate limit or a dropped connection.
RETRY_INTERVAL = 30 * 60


class UpdateError(ValueError):
    pass


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise UpdateError("The release has an unsupported version number.")
    parts = tuple(int(p) for p in value.split("."))
    if any(p > 65535 for p in parts):
        raise UpdateError("The release version exceeds Windows version limits.")
    return parts


def allowed_download_url(url):
    try:
        p = urlsplit(url)
        return (p.scheme == "https" and p.port in (None, 443) and not p.username
                and not p.password and not p.fragment and "\\" not in url
                and (url == LATEST_URL or
                     (p.hostname == "github.com" and p.path.startswith(f"/{REPOSITORY}/releases/download/")) or
                     p.hostname in {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Release:
    version: str
    notes: str
    url: str
    filename: str
    installer_url: str
    checksum_url: str
    size: int
    digest: str | None = None


def parse_release(data, current_version):
    """Only complete, newer, stable releases from the fixed repository qualify."""
    current = version_tuple(current_version)
    if not isinstance(data, dict):
        raise UpdateError("GitHub returned invalid release information.")
    if data.get("draft") is not False or data.get("prerelease") is not False:
        raise UpdateError("This is not a published stable release.")
    tag = data.get("tag_name", "")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise UpdateError("The release tag must start with v.")
    version = tag[1:]
    if version_tuple(version) <= current:
        return None
    filename = f"WinHardenSetup-{version}.exe"
    assets = data.get("assets")
    if not isinstance(assets, list):
        raise UpdateError("The release has no installer assets.")

    def asset(name, limit):
        matches = [a for a in assets if isinstance(a, dict) and a.get("name") == name]
        if len(matches) != 1:
            raise UpdateError(f"The release must contain exactly one {name}.")
        item = matches[0]
        expected = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        size = item.get("size")
        if (item.get("state") != "uploaded" or item.get("browser_download_url") != expected
                or type(size) is not int or not 0 < size <= limit):
            raise UpdateError(f"The release asset {name} is invalid or too large.")
        return item

    installer = asset(filename, MAX_INSTALLER)
    checksum = asset(filename + ".sha256", MAX_CHECKSUM)
    # Corroborates the published checksum when GitHub supplies it. Deliberately
    # optional: requiring it would strand every installed client if the API ever
    # stopped returning it, and release.py already refuses to publish without it.
    digest = installer.get("digest")
    if digest is not None:
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[a-fA-F0-9]{64}", digest):
            raise UpdateError("GitHub returned an invalid installer digest.")
        digest = digest[7:].lower()
    notes = data.get("body") or "No release notes were provided."
    if not isinstance(notes, str):
        raise UpdateError("The release notes are invalid.")
    return Release(version, notes, f"{RELEASES_URL}/tag/{tag}", filename,
                   installer["browser_download_url"], checksum["browser_download_url"],
                   installer["size"], digest)


def parse_checksum(raw, release):
    try:
        line = raw.decode("ascii").strip()
    except (UnicodeError, AttributeError) as exc:
        raise UpdateError("The installer checksum is invalid.") from exc
    match = re.fullmatch(r"([a-fA-F0-9]{64}) [ *]" + re.escape(release.filename), line)
    if not match:
        raise UpdateError("The checksum does not identify this installer.")
    checksum = match[1].lower()
    if release.digest and checksum != release.digest:
        raise UpdateError("GitHub's digest and the published checksum disagree.")
    return checksum


def cache_directory():
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    return Path(base) / "win-harden" / "updates"


def prune_cache(root, keep=None):
    """Drop staging directories from earlier attempts.

    A successful upgrade closes this app while setup is still running, so the
    directory it is using is deliberately left behind and nothing else ever
    removes it. One in use cannot be deleted, and is skipped.
    """
    keep = Path(keep).resolve() if keep is not None else None
    try:
        entries = sorted(Path(root).iterdir())
    except OSError:
        return
    for entry in entries:
        if not entry.is_dir() or entry.resolve() == keep:
            continue
        shutil.rmtree(entry, ignore_errors=True)


class InstallerDownload:
    """A unique staging directory; never reuse an executable from an earlier run."""

    def __init__(self, release, checksum, root=None):
        self.release = release
        self.checksum = checksum
        root = Path(root) if root is not None else cache_directory()
        root.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=release.version + "-", dir=root))
        prune_cache(root, keep=self.directory)
        self.partial = self.directory / (release.filename + ".partial")
        self.path = self.directory / release.filename
        self.file = self.partial.open("xb")
        self.count = 0
        self.hash = hashlib.sha256()

    def write(self, chunk):
        if self.count + len(chunk) > self.release.size:
            raise UpdateError("The installer download exceeds its published size.")
        self.file.write(chunk)
        self.count += len(chunk)
        self.hash.update(chunk)

    def finish(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()
        if self.count != self.release.size or self.hash.hexdigest() != self.checksum:
            raise UpdateError("Installer verification failed. Download it again.")
        os.replace(self.partial, self.path)
        return self.path

    def discard(self):
        try:
            self.file.close()
        except OSError:
            pass
        for path in (self.partial, self.path):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            self.directory.rmdir()
        except OSError:
            pass


class InstallerProcess:
    def __init__(self, handle):
        self.handle = handle

    def poll(self):
        import win32con
        import win32process
        code = win32process.GetExitCodeProcess(self.handle)
        return None if code == win32con.STILL_ACTIVE else code

    def close(self):
        self.handle.Close()


def verify_staged_installer(path, checksum):
    """Re-hash immediately before handing the file to Windows.

    The caller holds it open against writes and deletion, so this closes the
    window between verifying the download and executing it.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise UpdateError("The installer changed after verification. Download it again.")


def launch_installer(path, checksum):
    """Recheck while denying writes/deletion; let Inno elevate its own child.

    Using 'runas' here would lose Inno's original user and could relaunch the GUI
    elevated. An ordinary open preserves its unelevated bootstrap process.
    """
    import win32con
    import win32file
    from win32com.shell import shell, shellcon

    path = str(Path(path).resolve())
    handle = win32file.CreateFile(path, win32con.GENERIC_READ, win32con.FILE_SHARE_READ,
                                  None, win32con.OPEN_EXISTING, 0, None)
    try:
        verify_staged_installer(path, checksum)
        result = shell.ShellExecuteEx(fMask=shellcon.SEE_MASK_NOCLOSEPROCESS,
            lpVerb="open", lpFile=path, lpParameters="/NORESTART", lpDirectory=str(Path(path).parent),
            nShow=win32con.SW_SHOWNORMAL)
        process = result.get("hProcess")
        if not process:
            raise UpdateError("Windows did not return an installer process.")
        return InstallerProcess(process)
    finally:
        handle.Close()
