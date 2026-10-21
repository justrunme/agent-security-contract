"""``python -m asc`` entrypoint.

Must not run CLI side effects on import: test collectors and importlib walkers
may load ``asc.__main__`` with ``__name__ != "__main__"``.
"""

from asc.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
