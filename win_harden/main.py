"""Entry point."""

import sys


def main(argv=None):
    from .application import WinHardenApplication

    app = WinHardenApplication(list(argv if argv is not None else sys.argv))
    app.show_window()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
