"""Allow ``python -m cname_watch``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
