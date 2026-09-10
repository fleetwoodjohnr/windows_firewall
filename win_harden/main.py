"""Entry point."""

import sys


def main(argv=None):
    args = list(argv if argv is not None else sys.argv)
    if '--self-test' in args:
        from broker.selftest import check
        return check(gui=True)
    from .application import WinHardenApplication

    app = WinHardenApplication(list(argv if argv is not None else sys.argv))
    if not app.is_primary:
        return 0
    app.start(background='--background' in (argv if argv is not None else sys.argv))
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
