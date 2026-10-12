"""Background service installation: launchd (macOS), Startup folder (Windows), systemd --user / autostart (Linux)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

from .config import APP, LABEL, SYSTEM, app_dir, pid_file


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def service_command() -> list:
    """Command line that runs the service loop."""
    if frozen():  # PyInstaller binary: keep a stable copy outside Downloads/mounted images
        dest = app_dir() / "bin" / Path(sys.executable).name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.resolve() != Path(sys.executable).resolve():
            shutil.copy2(sys.executable, dest)
        return [str(dest), "run"]
    exe = Path(sys.executable)
    if SYSTEM == "Windows":  # no console window
        exe = exe.with_name("pythonw.exe") if exe.with_name("pythonw.exe").exists() else exe
        return [str(exe), "-m", "captive_autologin", "run"]
    script = shutil.which(APP)
    return [script, "run"] if script else [str(exe), "-m", "captive_autologin", "run"]


def _startup_vbs() -> Path:
    return (Path(os.environ.get("APPDATA", Path.home())) /
            "Microsoft/Windows/Start Menu/Programs/Startup" / f"{APP}.vbs")


def _plist() -> Path:
    return Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"


def _unit() -> Path:
    return Path.home() / ".config/systemd/user" / f"{APP}.service"


def _desktop() -> Path:
    return Path.home() / ".config/autostart" / f"{APP}.desktop"


def _quote(args) -> str:
    return " ".join('"%s"' % a for a in args)


def install_service() -> str:
    cmd = service_command()
    if SYSTEM == "Darwin":
        plist = _plist()
        plist.parent.mkdir(parents=True, exist_ok=True)
        args = "".join(f"<string>{escape(a)}</string>" for a in cmd)
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{LABEL}</string>
    <key>ProgramArguments</key><array>{args}</array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ThrottleInterval</key><integer>10</integer>
    <key>StandardErrorPath</key><string>{escape(str(app_dir() / "service.err"))}</string>
</dict>
</plist>
""")
        domain = f"gui/{os.getuid()}"
        subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", domain, str(plist)], check=True)
        return "LaunchAgent " + str(plist)

    if SYSTEM == "Windows":
        stop_windows_process()
        vbs = _startup_vbs()
        vbs.parent.mkdir(parents=True, exist_ok=True)
        run = " ".join('""%s""' % a for a in cmd)
        vbs.write_text('Set sh = CreateObject("WScript.Shell")\r\n' f'sh.Run "{run}", 0, False\r\n')
        subprocess.Popen(cmd, close_fds=True, creationflags=0x00000008 | 0x00000200)  # DETACHED | NEW_GROUP
        return "Startup script " + str(vbs)

    if shutil.which("systemctl") and subprocess.run(["systemctl", "--user", "show-environment"],
                                                    capture_output=True).returncode == 0:
        unit = _unit()
        unit.parent.mkdir(parents=True, exist_ok=True)
        unit.write_text(f"""[Unit]
Description=Captive portal auto-login
After=network-online.target

[Service]
ExecStart={_quote(cmd)}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
""")
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "--user", "enable", "--now", f"{APP}.service"], check=True)
        subprocess.run(["systemctl", "--user", "restart", f"{APP}.service"], check=True)
        return "systemd user service " + str(unit) + " (headless boot: loginctl enable-linger $USER)"

    desktop = _desktop()
    desktop.parent.mkdir(parents=True, exist_ok=True)
    desktop.write_text(f"[Desktop Entry]\nType=Application\nName=Captive portal autologin\n"
                       f"Exec={_quote(cmd)}\nX-GNOME-Autostart-enabled=true\n")
    subprocess.Popen(cmd, start_new_session=True, close_fds=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return "autostart " + str(desktop)


def stop_windows_process():
    try:
        pid = int(pid_file().read_text())
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    except (OSError, ValueError):
        pass
    pid_file().unlink(missing_ok=True)


def uninstall_service():
    if SYSTEM == "Darwin":
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], capture_output=True)
        _plist().unlink(missing_ok=True)
    elif SYSTEM == "Windows":
        stop_windows_process()
        _startup_vbs().unlink(missing_ok=True)
    else:
        if shutil.which("systemctl"):
            subprocess.run(["systemctl", "--user", "disable", "--now", f"{APP}.service"], capture_output=True)
            _unit().unlink(missing_ok=True)
        _desktop().unlink(missing_ok=True)
        subprocess.run(["pkill", "-f", f"{APP}.* run"], capture_output=True)
    shutil.rmtree(app_dir() / "bin", ignore_errors=True)
