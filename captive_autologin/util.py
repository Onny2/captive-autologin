"""Small OS helpers: desktop notifications and opening files."""

from __future__ import annotations

import os
import shutil
import subprocess

from .config import SYSTEM


def notify(title, message):
    try:
        if SYSTEM == "Darwin":
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
            subprocess.run(["osascript", "-e",
                            f'display notification "{esc(message)}" with title "{esc(title)}"'],
                           capture_output=True, timeout=10)
        elif SYSTEM == "Linux" and shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def open_path(path):
    try:
        if SYSTEM == "Windows":
            os.startfile(str(path))  # noqa: S606
        elif SYSTEM == "Darwin":
            subprocess.run(["open", str(path)], capture_output=True, timeout=10)
        elif shutil.which("xdg-open"):
            subprocess.run(["xdg-open", str(path)], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass
