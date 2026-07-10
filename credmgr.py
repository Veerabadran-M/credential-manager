#!/usr/bin/env python3
"""Entry point wrapper so the tool can be run as `./credmgr.py` or
`python credmgr.py`, without installing the package."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from credmgr.cli import main  # noqa: E402

if __name__ == "__main__":
    main()