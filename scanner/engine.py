"""Fixed Defender commands and conservative scan-result interpretation."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading

from .paths import system_powershell
from broker.winprocess import creation_flags

PS_ROOT = Path(__file__).resolve().parent / "ps"


def fingerprint(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError("The scan target is no longer a regular file.")
    before = p.stat()
    h = hashlib.sha256()
    with p.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    after = p.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("The file changed while it was being read; it needs another scan.")
    return {"sha256": h.hexdigest(), "size": after.st_size, "mtime_ns": after.st_mtime_ns,
            "file_id": after.st_ino}


def classify(result, before=None, after=None):
    result = dict(result)
    threats = result.get("threats") or []
    if result.get("error"):
        result.update(state="failed", message=result["error"])
    elif any(t.get("active") or not t.get("actionSuccess") for t in threats):
        result.update(state="action_required", message="Defender detected threats requiring attention.")
    elif threats and result.get("exitCode") == 0 and result.get("scanCompleted"):
        result.update(state="remediated", message="Defender reports that detected threats were remediated.")
    elif result.get("exitCode") != 0:
        result.update(state="failed", message="Defender did not complete successfully. No clean result is available.")
    elif result.get("excluded"):
        result.update(state="incomplete", message="This file is excluded from Defender scanning.")
    elif not result.get("scanCompleted"):
        result.update(state="incomplete", message="Scan completion could not be verified in Defender's event log.")
    elif before is not None and before != after:
        result.update(state="incomplete", message="The file changed or disappeared during scanning; rescan required.")
    else:
        result.update(state="clean", message="No threats detected. This does not guarantee a file is safe.")
    if before:
        result["fingerprint"] = before
    return result


class DefenderEngine:
    def __init__(self):
        self.processes = set()
        self.lock = threading.Lock()
        self.stopping = threading.Event()

    def _script(self, name, params=(), timeout=60):
        if name not in ("status.ps1", "operation.ps1"):
            raise ValueError("Unknown Defender script")
        argv = [system_powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", str(PS_ROOT / name), *params]
        if self.stopping.is_set():
            raise RuntimeError("The scan service is stopping.")
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, creationflags=creation_flags())
        job = None
        if os.name == 'nt':
            # Closing the job also closes MpCmdRun descendants and their pipe
            # handles; killing only PowerShell can leave communicate() blocked.
            import win32job
            try:
                job = win32job.CreateJobObject(None, None)
                limits = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
                limits['BasicLimitInformation']['LimitFlags'] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, limits)
                win32job.AssignProcessToJobObject(job, int(process._handle))
            except Exception:
                if job:
                    job.Close()
                process.kill()
                raise
        with self.lock:
            self.processes.add((process, job))
        try:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                if job:
                    win32job.TerminateJobObject(job, 1)
                else:
                    process.kill()
                process.communicate()
                raise RuntimeError("Defender did not finish within the operation time limit; completion is unverified.") from None
            if process.returncode:
                raise RuntimeError(stderr.decode("utf-8", "replace").strip()[-1500:] or "Defender command failed.")
            result = json.loads(stdout.decode("utf-8-sig"))
            if not isinstance(result, dict):
                raise ValueError("Invalid Defender response")
            return result
        finally:
            with self.lock:
                self.processes.discard((process, job))
                if job:
                    job.Close()

    def health(self):
        return self._script("status.ps1")

    def run(self, kind, path=""):
        health = self.health()
        if not health.get("available"):
            raise RuntimeError(health.get("error") or "Microsoft Defender is unavailable. Open Windows Security.")
        before = fingerprint(path) if path else None
        params = ["-Operation", kind]
        if path:
            params += ["-LiteralPath", path]
        result = self._script("operation.ps1", params,
                              timeout=7 * 86400 if kind == "full" else 86400 if kind in ("quick", "custom") else 900)
        result.setdefault("signatureVersion", health.get("signatureVersion"))
        result.setdefault("signatureAgeDays", health.get("signatureAgeDays"))
        if kind in ("update", "protect", "remediate"):
            return result
        after = None
        if path:
            try:
                after = fingerprint(path)
            except (OSError, ValueError):
                pass
        return classify(result, before, after)

    def stop(self):
        self.stopping.set()
        with self.lock:
            for process, job in list(self.processes):
                try:
                    if job:
                        import win32job
                        win32job.TerminateJobObject(job, 1)
                    else:
                        process.kill()
                except OSError:
                    pass
