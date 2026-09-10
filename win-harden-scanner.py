"""Frozen Windows service entry point."""
if __name__ == '__main__':
    import sys
    if '--self-test' in sys.argv:
        from broker.selftest import check
        sys.exit(check())
    from scanner.service import main
    sys.exit(main())
