"""Durable scan queue. One engine operation at a time, short IPC requests."""
import json
import sqlite3
import threading
import time
import uuid
from contextlib import nullcontext

TERMINAL = {"clean", "remediated", "action_required", "incomplete", "failed", "cancelled", "completed"}


class Jobs:
    def __init__(self, path, engine):
        self.engine = engine
        self.lock = threading.RLock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, request TEXT NOT NULL,
            kind TEXT NOT NULL, path TEXT NOT NULL, state TEXT NOT NULL,
            created REAL NOT NULL, updated REAL NOT NULL, result TEXT NOT NULL,
            UNIQUE(owner,request))""")
        self.db.execute("UPDATE jobs SET state='incomplete', result=? WHERE state='running'",
                        (json.dumps({"message": "The service restarted before scan completion could be verified."}),))
        # After restart, caller impersonation is no longer available: custom
        # files must be re-authorized by the user's monitor, not replayed as SYSTEM.
        self.db.execute("UPDATE jobs SET state='incomplete', result=? WHERE state='queued' AND kind='custom'",
                        (json.dumps({"message": "Resubmit this file after service restart to verify access."}),))
        self.db.commit()
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        self.authorizations = {}

    def start(self):
        self.thread = threading.Thread(target=self._loop, name="defender-jobs", daemon=True)
        self.thread.start()

    def submit(self, owner, kind, request, path="", authorization=None):
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE owner=? AND request=?", (owner, request)).fetchone()
            if row:
                if authorization:
                    authorization.close()
                if row["kind"] != kind or row["path"] != path:
                    raise ValueError("Request identifier was already used for a different scan.")
                return self._record(row)
            count = self.db.execute("SELECT count(*) FROM jobs WHERE owner=? AND state IN ('queued','running')",
                                    (owner,)).fetchone()[0]
            if count >= 128:
                if authorization:
                    authorization.close()
                raise ValueError("The scan queue is full. Pending downloads will be retried.")
            job = str(uuid.uuid4())
            now = time.time()
            self.db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                            (job, owner, request, kind, path, "queued", now, now, "{}"))
            self.db.commit()
            if authorization:
                self.authorizations[job] = authorization
            self.wake.set()
            return self.get(owner, job)

    @staticmethod
    def _record(row):
        data = dict(row)
        data["result"] = json.loads(data["result"])
        data.pop("owner", None)
        data.pop("request", None)
        return data

    def get(self, owner, job):
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE owner=? AND id=?", (owner, job)).fetchone()
            if row is None:
                raise ValueError("Scan job not found for this user.")
            return self._record(row)

    def history(self, owner):
        with self.lock:
            return [self._record(r) for r in self.db.execute(
                "SELECT * FROM jobs WHERE owner=? ORDER BY created DESC LIMIT 100", (owner,))]

    def cancel(self, owner, job):
        with self.lock:
            row = self.get(owner, job)
            if row["state"] == "running":
                raise ValueError("This scan is already running. Windows Security can stop a system scan.")
            if row["state"] == "queued":
                self._finish(job, "cancelled", {"message": "Cancelled before scanning."})
                auth = self.authorizations.pop(job, None)
                if auth:
                    auth.close()
            return self.get(owner, job)

    def _finish(self, job, state, result):
        self.db.execute("UPDATE jobs SET state=?, updated=?, result=? WHERE id=?",
                        (state, time.time(), json.dumps(result), job))
        self.db.commit()

    def run_one(self):
        with self.lock:
            row = self.db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None:
                return False
            self._finish(row["id"], "running", {})
        try:
            auth = self.authorizations.pop(row['id'], None)
            with auth if auth else nullcontext():
                result = self.engine.run(row["kind"], row["path"])
            state = result.get("state", "incomplete")
            if state not in TERMINAL:
                raise ValueError("The antivirus returned an unknown result.")
        except Exception as exc:
            state, result = "failed", {"message": str(exc)}
        with self.lock:
            self._finish(row["id"], state, result)
            self.db.execute("DELETE FROM jobs WHERE updated < ? AND state NOT IN ('queued','running')",
                            (time.time() - 30 * 86400,))
            self.db.commit()
        return True

    def _loop(self):
        while not self.stop_event.is_set():
            if not self.run_one():
                self.wake.wait(2)
                self.wake.clear()

    def stop(self):
        self.stop_event.set()
        self.wake.set()
        self.engine.stop()
        if self.thread:
            self.thread.join(10)
        if not self.thread or not self.thread.is_alive():
            for auth in self.authorizations.values():
                auth.close()
            self.authorizations.clear()
            self.db.close()
