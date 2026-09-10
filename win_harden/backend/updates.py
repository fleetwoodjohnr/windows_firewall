"""Asynchronous GitHub update checks and downloads, owned by the application."""

import json
import os
import sys
import time

from PySide6.QtCore import QObject, QTimer, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkReply, QNetworkRequest

from ..updates import (CHECK_INTERVAL, LATEST_URL, MAX_CHECKSUM, MAX_METADATA,
                       InstallerDownload, UpdateError, allowed_download_url,
                       launch_installer, parse_checksum, parse_release)
from ..version import VERSION


class HttpTransfer(QObject):
    """One bounded request, including redirects. Completion is delivered once."""

    def __init__(self, network, url, limit, done, chunk=None, parent=None):
        super().__init__(parent)
        self.network, self.limit, self.done, self.chunk = network, limit, done, chunk
        self.reply = None
        self.data = bytearray()
        self.count = 0
        self.redirects = 0
        self.finished = False
        self.deadline = QTimer(self)
        self.deadline.setSingleShot(True)
        self.deadline.timeout.connect(lambda: self.finish(0, "The update request timed out."))
        self.deadline.start(30 * 60 * 1000 if chunk else 30000)
        self.request(url)

    def request(self, url):
        if not allowed_download_url(url):
            self.finish(0, "The update download redirected to an untrusted address.")
            return
        request = QNetworkRequest(QUrl(url))
        request.setRawHeader(b"User-Agent", ("WinHarden/" + VERSION).encode())
        request.setRawHeader(b"Accept", b"application/vnd.github+json" if url == LATEST_URL else b"application/octet-stream")
        request.setRawHeader(b"Accept-Encoding", b"identity")
        request.setTransferTimeout(60000 if self.chunk else 30000)
        request.setAttribute(QNetworkRequest.RedirectPolicyAttribute, QNetworkRequest.ManualRedirectPolicy)
        self.reply = self.network.get(request)
        self.reply.setReadBufferSize(256 * 1024)
        self.reply.readyRead.connect(self.read)
        self.reply.finished.connect(self.complete)

    def read(self):
        if self.finished:
            return
        status = self.reply.attribute(QNetworkRequest.HttpStatusCodeAttribute)
        if status != 200:
            self.reply.readAll()
            return
        try:
            while self.reply.bytesAvailable():
                data = bytes(self.reply.read(256 * 1024))
                self.count += len(data)
                if self.count > self.limit:
                    raise UpdateError("The update response exceeds its allowed size.")
                if self.chunk:
                    self.chunk(data)
                else:
                    self.data.extend(data)
        except (OSError, ValueError) as exc:
            self.finish(0, str(exc))

    def complete(self):
        if self.finished:
            return
        self.read()
        if self.finished:
            return
        reply = self.reply
        status = reply.attribute(QNetworkRequest.HttpStatusCodeAttribute) or 0
        redirect = reply.attribute(QNetworkRequest.RedirectionTargetAttribute)
        if status in (301, 302, 303, 307, 308) and redirect is not None:
            self.redirects += 1
            if self.redirects > 5:
                self.finish(0, "Too many redirects while downloading the update.")
                return
            url = reply.url().resolved(redirect).toString()
            reply.deleteLater()
            self.reply = None
            self.request(url)
            return
        if status == 200 and reply.error() == QNetworkReply.NoError:
            self.finish(status, None)
        elif status in (403, 429):
            self.finish(status, "GitHub refused or rate-limited the update check. Try again later.")
        elif status == 404:
            self.finish(status, "The release or installer could not be found.")
        else:
            self.finish(status, "Could not download the update: " + reply.errorString())

    def finish(self, status, error):
        if self.finished:
            return
        self.finished = True
        self.deadline.stop()
        if self.reply:
            if self.reply.isRunning():
                self.reply.abort()
            self.reply.deleteLater()
            self.reply = None
        self.done(bytes(self.data), status, error)
        self.deleteLater()

    def cancel(self):
        self.finish(0, "Cancelled.")


class UpdateManager(QObject):
    changed = Signal()
    progress = Signal(int, int)
    available = Signal(str)
    installer_started = Signal()

    def __init__(self, settings, parent=None, *, transport=None, launcher=None,
                 installed=None, clock=time.time, cache=None, busy=lambda: False):
        super().__init__(parent)
        self.settings, self.clock, self.cache, self.security_busy = settings, clock, cache, busy
        self.installed = (os.name == "nt" and bool(getattr(sys, "frozen", False))) if installed is None else installed
        self.network = QNetworkAccessManager(self)
        self.transport = transport or self._transfer
        self.launcher = launcher or launch_installer
        self.state = "idle"
        self.message = "Check for a newer version of the application."
        self.release = None
        self.latest_version = None
        self.checksum = None
        self.download = None
        self.request = None
        self._generation = 0
        self._closed = False
        self.setup_process = None
        self.setup_timer = QTimer(self)
        self.setup_timer.timeout.connect(self._poll_setup)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_if_due)
        self.startup = QTimer(self)
        self.startup.setSingleShot(True)
        self.startup.timeout.connect(self.check_if_due)

    @property
    def active(self):
        return self.state in {"checking", "downloading", "launching", "launched"}

    def _transfer(self, url, limit, done, chunk=None):
        return HttpTransfer(self.network, url, limit, done, chunk, self)

    def start(self):
        if self.installed:
            self.startup.start(10000)
            self.timer.start(60000)

    def set_automatic(self, enabled):
        self.settings.check_updates_automatically = bool(enabled)
        if enabled:
            self.check_if_due()

    def check_if_due(self):
        now = int(self.clock())
        last = self.settings.updates_last_attempt
        if (self.installed and self.settings.check_updates_automatically
                and not self.active and self.state != "ready"
                and (last <= 0 or now < last or now - last >= CHECK_INTERVAL)):
            self.check()

    def _status(self, state, message):
        self.state, self.message = state, message
        self.changed.emit()

    def _get(self, url, limit, done, chunk=None):
        generation = self._generation

        def completed(raw, status, error):
            if generation != self._generation or self._closed:
                return
            self.request = None
            try:
                done(raw, status, error)
            except (ValueError, OSError) as exc:
                self._failed(str(exc))
        self.request = self.transport(url, limit, completed, chunk)

    def check(self):
        if self.active or self._closed:
            return
        self._discard()
        self.release, self.checksum = None, None
        self.latest_version = None
        self.settings.updates_last_attempt = int(self.clock())
        self._status("checking", "Checking GitHub Releases…")
        self._get(LATEST_URL, MAX_METADATA, self._checked)

    def _checked(self, raw, status, error):
        if status == 404:
            self._status("idle", "No application releases have been published yet.")
            return
        if error:
            self._failed(error)
            return
        data = json.loads(raw)
        self.release = parse_release(data, VERSION)
        self.latest_version = data['tag_name'][1:]
        if self.release is None:
            self.settings.updates_last_checked = int(self.clock())
            self._status("current", "No newer published version is available.")
            return
        self._get(self.release.checksum_url, MAX_CHECKSUM, self._checksum_received)

    def _checksum_received(self, raw, status, error):
        if error:
            self._failed(error)
            return
        self.checksum = parse_checksum(raw, self.release)
        self.settings.updates_last_checked = int(self.clock())
        self._status("available", f"Version {self.release.version} is available.")
        if self.settings.updates_notified_version != self.release.version:
            self.settings.updates_notified_version = self.release.version
            self.available.emit(self.release.version)

    def update(self):
        if self.active or self._closed or not self.release or not self.checksum:
            return
        if not self.installed:
            self._status("available", "Install updates from the installed Windows application. Development checkouts cannot install updates.")
            return
        if self.security_busy():
            self._status("ready" if self.download else "available", "Wait for the current security change to finish, then click Update again.")
            return
        if self.state == "ready" and self.download:
            self._launch()
            return
        try:
            self._discard()
            self.download = InstallerDownload(self.release, self.checksum, self.cache)
        except OSError as exc:
            self._failed("Could not create the update download: " + str(exc))
            return
        self._status("downloading", "Downloading the update… You can cancel before setup opens.")
        self.progress.emit(0, self.release.size)

        def chunk(data):
            self.download.write(data)
            self.progress.emit(self.download.count, self.release.size)
        self._get(self.release.installer_url, self.release.size, self._downloaded, chunk)

    def _downloaded(self, raw, status, error):
        if error:
            self._failed(error)
            return
        self.download.finish()
        self._status("ready", "Download verified. Ready to open the upgrade wizard.")
        if self.security_busy():
            self._status("ready", "Download verified. Wait for the security change to finish, then click Update again.")
            return
        self._launch()

    def _launch(self):
        self._status("launching", "Opening the upgrade wizard…")
        try:
            self.setup_process = self.launcher(self.download.path, self.checksum)
        except Exception as exc:
            if getattr(exc, "winerror", None) == 1223:
                self._status("ready", "Administrator approval was cancelled. Click Update to try again.")
            else:
                self._failed("Could not open setup: " + str(exc))
            return
        # Setup has its own lifetime. Keep the verified executable for it.
        self._status("launched", "Setup opened. Complete the wizard to update the application.")
        if self.setup_process:
            self.setup_timer.start(500)
        self.installer_started.emit()

    def _poll_setup(self):
        try:
            code = self.setup_process.poll()
        except OSError as exc:
            self.setup_timer.stop()
            self.setup_process.close()
            self.setup_process = None
            self._status("error", "Could not read setup's result: " + str(exc))
            return
        if code is None:
            return
        self.setup_timer.stop()
        self.setup_process.close()
        self.setup_process = None
        self._discard()
        # The GUI stays alive until Restart Manager requests a real shutdown.
        # Consequently UAC or wizard cancellation cannot stop its monitoring.
        self._status("available", "Setup closed. If the update was cancelled, click Update to try again."
                     if code in (0, 1, 2, 1223) else f"Setup failed (code {code}). Retry the installer to repair the application.")

    def _discard(self):
        if self.download:
            self.download.discard()
            self.download = None

    def _failed(self, error):
        self._discard()
        self._status("error", error)

    def cancel(self):
        if self.state in {"launching", "launched"}:
            return
        self._generation += 1
        request, self.request = self.request, None
        if request:
            request.cancel()
        self._discard()
        self._status("available" if self.release and self.checksum else "idle", "Update cancelled. Your installed application has not changed.")

    def shutdown(self):
        self._closed = True
        self.timer.stop()
        self.startup.stop()
        self.setup_timer.stop()
        if self.setup_process:
            self.setup_process.close()
            self.setup_process = None
            # Do not delete the executable while setup is using it.
            self.download = None
        self.cancel()
