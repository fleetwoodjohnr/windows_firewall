"""Broker entry point. Packaged by PyInstaller as win-harden-broker.exe with a
requireAdministrator manifest, so launching it raises exactly one UAC prompt."""

import sys

from broker.broker import main

if __name__ == "__main__":
    sys.exit(main())
