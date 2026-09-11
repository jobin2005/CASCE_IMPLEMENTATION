#!/usr/bin/env python3
"""
Root entrypoint shim for main.py (CASCE Master Graph Pipeline).
Redirects execution to src/main.py for backward compatibility.
"""
import sys
from pathlib import Path

# Setup paths
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.main import main

if __name__ == "__main__":
    main()
