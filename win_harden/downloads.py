"""Per-user durable download monitor, running without elevation.

Polling is intentional: reconciliation also catches downloads made while the
app was stopped and does not lose events when Windows notification buffers fill.
Only stable regular files are queued. Defender remains the on-access blocker.
"""
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
import uuid

from scanner import client
from scanner.jobs import TERMINAL

PARTIAL_SUFFIXES = ('.crdownload', '.part', '.partial', '.download')
SETTLE_SECONDS = 3
RETRY_SECONDS = 60


def file_stamp(path):
    stat = path.stat(follow_symlinks=False)
    if not path.is_file() or path.is_symlink() or getattr(stat, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Linked or non-regular file')
    return json.dumps([stat.st_ino, stat.st_size, stat.st_mtime_ns])


def walk_files(root, errors):
    root = Path(root)
    if not root.exists():
        errors.append(f'{root}: folder unavailable')
        return
    if root.is_symlink() or getattr(root.stat(), 'st_file_attributes', 0) & 0x400:
        errors.append(f'{root}: linked folders are not monitored')
        return
    def failed(exc):
        errors.append(str(exc))
    for directory, folders, files in os.walk(root, followlinks=False, onerror=failed):
        safe = []
        for name in folders:
            p = Path(directory) / name
            try:
                if p.is_symlink() or getattr(p.stat(follow_symlinks=False), 'st_file_attributes', 0) & 0x400:
                    errors.append(f'{p}: linked folder skipped')
                else:
                    safe.append(name)
            except OSError as exc:
                errors.append(str(exc))
        folders[:] = safe
        for name in files:
            yield Path(directory) / name


class DownloadMonitor:
    def __init__(self, database, roots, submit=client.submit, request=client.request, notify=None):
        self.database = str(database)
        self.roots = list(roots)
        self.submit_scan = submit
        self.request = request
        self.notify = notify or (lambda *_: None)
        self.stop_event = threading.Event()
        self.paused = False
        self.status = 'Starting download monitor'
        self.errors = []
        self.thread = None
        self.extra_files = []
        self.lock = threading.Lock()

    def connect(self):
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.database)
        self.db.row_factory = sqlite3.Row
        self.db.execute('''CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY, stamp TEXT NOT NULL, observed REAL NOT NULL,
            request TEXT NOT NULL, job TEXT, state TEXT NOT NULL, retry REAL NOT NULL,
            message TEXT NOT NULL)''')
        self.db.commit()

    def enqueue_folder(self, path):
        # Adding a folder here means scan once. Persistent watched roots are
        # managed separately in preferences.
        with self.lock:
            self.extra_files.append(str(path))

    def set_roots(self, roots):
        with self.lock:
            self.roots = list(roots)

    def reconcile(self, now=None):
        now = time.time() if now is None else now
        self.errors = []
        with self.lock:
            roots = list(self.roots)
            extras, self.extra_files = self.extra_files, []
        for root in roots + extras:
            try:
                for path in walk_files(root, self.errors):
                    if self.stop_event.is_set():
                        return
                    try:
                        stamp = file_stamp(path)
                    except (OSError, ValueError) as exc:
                        self.errors.append(f'{path}: {exc}')
                        continue
                    key = str(path)
                    row = self.db.execute('SELECT * FROM files WHERE path=?', (key,)).fetchone()
                    partial = key.lower().endswith(PARTIAL_SUFFIXES)
                    if row is None or row['stamp'] != stamp or root in extras:
                        self.db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?,?)',
                            (key, stamp, now, str(uuid.uuid4()), None, 'downloading' if partial else 'waiting', 0, ''))
                    elif row['state'] == 'downloading' and not partial:
                        self.db.execute("UPDATE files SET state='waiting',observed=? WHERE path=?", (now, key))
            except OSError as exc:
                self.errors.append(f'{root}: {exc}')
        for row in self.db.execute("SELECT path FROM files WHERE state='downloading'").fetchall():
            if not Path(row['path']).exists():
                self.db.execute('DELETE FROM files WHERE path=?', (row['path'],))
        self.db.commit()

    def process(self, now=None):
        now = time.time() if now is None else now
        # Bound each pass so a large folder cannot delay shutdown indefinitely.
        rows = self.db.execute("SELECT * FROM files WHERE state IN ('waiting','queued','running','retry') AND retry<=? ORDER BY observed LIMIT 16", (now,)).fetchall()
        for row in rows:
            if self.stop_event.is_set():
                break
            try:
                path = Path(row['path'])
                stamp = file_stamp(path)
                if row['stamp'] != stamp:
                    self.db.execute("UPDATE files SET stamp=?,observed=?,request=?,job=NULL,state='waiting' WHERE path=?",
                                    (stamp, now, str(uuid.uuid4()), str(path)))
                    continue
                if not row['job']:
                    if now - row['observed'] < SETTLE_SECONDS:
                        continue
                    if row['state'] == 'retry':
                        # A failed attempt must receive a fresh id; an IPC
                        # timeout with no response retains the old id below.
                        pass
                    job = self.submit_scan('custom', str(path), request_id=row['request'])
                else:
                    job = self.request('job', job_id=row['job'])
                state = job['state']
                message = (job.get('result') or {}).get('message', '')
                retry = 0
                request_id = row['request']
                job_id = job['id']
                if state in ('failed', 'incomplete') and not (job.get('result') or {}).get('excluded'):
                    retry, request_id, job_id = now + RETRY_SECONDS, str(uuid.uuid4()), None
                    state = 'retry'
                self.db.execute('UPDATE files SET job=?,state=?,retry=?,request=?,message=? WHERE path=?',
                                (job_id, state, retry, request_id, message, str(path)))
                if job['state'] in ('remediated', 'action_required') and row['state'] != job['state']:
                    self.notify('Download threat detected', f'{path.name}: {message}')
            except (FileNotFoundError, ValueError) as exc:
                # Defender may already have quarantined the source. Query its
                # submitted job before calling a missing download incomplete.
                if row['job']:
                    try:
                        job = self.request('job', job_id=row['job'])
                        if job['state'] in TERMINAL:
                            self.db.execute('UPDATE files SET state=?,message=? WHERE path=?',
                                (job['state'], job.get('result', {}).get('message', ''), row['path']))
                            if job['state'] in ('remediated', 'action_required'):
                                self.notify('Download threat detected', f"{path.name}: {job.get('result', {}).get('message', '')}")
                            continue
                    except Exception:
                        pass
                self.db.execute("UPDATE files SET state='incomplete',message=? WHERE path=?", (str(exc), row['path']))
            except Exception as exc:
                if 'not found for this user' in str(exc):
                    self.db.execute("UPDATE files SET job=NULL,request=?,state='retry' WHERE path=?",
                                    (str(uuid.uuid4()), row['path']))
                self.db.execute('UPDATE files SET retry=?,message=? WHERE path=?', (now + RETRY_SECONDS, str(exc), row['path']))
                self.errors.append(str(exc))
                break
        self.db.commit()

    def start(self):
        self.thread = threading.Thread(target=self._loop, name='download-monitor', daemon=True)
        self.thread.start()

    def _loop(self):
        self.connect()
        try:
            while not self.stop_event.is_set():
                if self.paused:
                    self.status = 'Additional download scans paused; Defender runs independently'
                else:
                    try:
                        self.reconcile()
                        self.process()
                        count = self.db.execute("SELECT count(*) FROM files WHERE state IN ('waiting','queued','running','retry','downloading')").fetchone()[0]
                        incomplete = self.db.execute("SELECT count(*) FROM files WHERE state IN ('incomplete','action_required','failed')").fetchone()[0]
                        self.status = f'{count} download(s) pending; {incomplete} need attention'
                        if self.errors:
                            self.status += ' — ' + self.errors[0]
                    except Exception as exc:
                        self.status = f'Download monitoring needs attention: {exc}'
                self.stop_event.wait(3)
        finally:
            self.db.close()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(1)
