#!/usr/bin/env python3
"""
Root entrypoint shim for run_pipeline.py (CASCE End-to-End Pipeline Orchestrator).
Redirects execution to src/run_pipeline.py for backward compatibility.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.run_pipeline import main

if __name__ == "__main__":
    main()
