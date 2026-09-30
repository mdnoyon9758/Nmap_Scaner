#!/usr/bin/env python3
"""
ReconX launcher.

Run the unified toolkit directly from a source checkout without installing:

    python3 recon.py example.com --profile recon --i-am-authorized

For authorized security assessment only.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reconx.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
