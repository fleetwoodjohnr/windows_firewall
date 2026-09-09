r"""The elevated broker.

Started by the GUI through UAC, runs as Administrator, and serves exactly one
client over one named pipe for as long as that client is there. This file is
deliberately thin -- all of the decision-making lives in `dispatch.py`, which is
testable without Windows -- so that what runs elevated is a transport loop and
little else.

    win-harden-broker.exe --client-sid S-1-5-21-...

Design rules carried over from the Fedora app's privileged helper, all of them
load-bearing:

  * The only thing accepted from the caller is a verb and values drawn from
    fixed lists (`protocol.py`). No paths, no addresses, no free text.
  * Never a shell. Every external call goes through `psinvoke.build_argv`.
  * The tables in `actions/` are authoritative. The GUI's copies under
    `win_harden/data/` are display mirrors and are never trusted.
  * Every change is journalled before it is made, so it can be undone exactly
    (`registry_txn.py`).

It exits when the client disconnects, and after an idle period, so an elevated
process is not left sitting around after the app is closed.
"""

import argparse
import os
import sys
import time

# Running as a PyInstaller one-file build, the package root is the extraction
# directory; running from a checkout it is the parent of this file. Resolve it
# from __file__ either way, never from the working directory -- an elevated
# process must not take the location of its own code from anything a
# lower-privileged caller can influence.
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

from broker import pipe as pipe_module  # noqa: E402
from broker.actions import load_families  # noqa: E402
from broker.dispatch import Context, Dispatcher  # noqa: E402
from broker.guards import WindowsProbes  # noqa: E402
from broker.protocol import ProtocolError, decode_frame, encode_response  # noqa: E402
from broker.psrun import make_runner  # noqa: E402
from broker.registry_txn import StateStore, WinRegBackend  # noqa: E402

STATE_DIR = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "win-harden")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_FILE = os.path.join(STATE_DIR, "broker.log")

# The GUI is expected to hold the connection open for the life of the app. This
# only catches the case where it vanished without closing cleanly.
IDLE_TIMEOUT_SECONDS = 15 * 60


def make_logger(path):
    """Append-only log. A broker that cannot write its log still runs -- losing
    diagnostics is not a reason to leave a machine un-revertable."""

    def log(message):
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp} {message}\n"
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass
        sys.stderr.write(line)

    return log


def build_context(log):
    runner = make_runner()
    return Context(
        store=StateStore(STATE_FILE),
        registry=WinRegBackend(),
        probes=WindowsProbes(runner),
        families=load_families(),
        runner=runner,
        log=log,
    )


def serve(server, dispatcher, log, idle_timeout=IDLE_TIMEOUT_SECONDS):
    """Read frames until the client goes away or asks us to stop.

    Every frame gets a response, including one we could not parse: a client left
    waiting on a reply that never comes is a control greyed out forever.
    """
    last_activity = time.monotonic()
    while not dispatcher.should_exit:
        line = server.read_frame()
        if line is None:
            log("client disconnected")
            return
        last_activity = time.monotonic()

        try:
            payload = decode_frame(line)
        except ProtocolError as e:
            server.write_frame(
                encode_response("unknown", False, error_kind=e.kind, error_message=str(e))
            )
            continue

        server.write_frame(dispatcher.handle_frame(payload))

        if time.monotonic() - last_activity > idle_timeout:
            log("idle timeout")
            return


def main(argv=None):
    parser = argparse.ArgumentParser(prog="win-harden-broker", add_help=True)
    parser.add_argument(
        "--client-sid",
        required=True,
        help="SID of the user this broker serves. Used both to build the pipe's "
             "DACL and to verify the connecting client's token.",
    )
    args = parser.parse_args(argv)

    log = make_logger(LOG_FILE)

    try:
        pipe_module.validate_sid(args.client_sid)
    except pipe_module.PipeError as e:
        log(f"refusing to start: {e}")
        return 2

    if os.name != "nt":
        log("this broker only runs on Windows")
        return 2

    os.makedirs(STATE_DIR, exist_ok=True)
    log(f"starting for {args.client_sid}")

    server = pipe_module.PipeServer(args.client_sid)
    try:
        server.create()
        server.wait_for_client()
        log("client connected and verified")
        serve(server, Dispatcher(build_context(log)), log)
    except pipe_module.AccessRefused as e:
        log(str(e))
        return 3
    except Exception as e:  # noqa: BLE001 - log before dying, or debugging this is guesswork
        import traceback

        log(f"fatal: {traceback.format_exc()}")
        sys.stderr.write(f"{e}\n")
        return 1
    finally:
        server.close()
        log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
