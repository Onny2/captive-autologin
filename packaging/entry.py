"""PyInstaller entry point (double-clicking the binary starts the install wizard)."""

import sys

from captive_autologin.cli import main

sys.exit(main())
