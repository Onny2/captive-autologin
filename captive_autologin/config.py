"""Paths, defaults and JSON config/state helpers."""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path

APP = "captive-autologin"
LABEL = "io.github.captive-autologin"
SYSTEM = platform.system()  # "Windows", "Darwin", "Linux"

DEFAULTS = {
    "username": "",
    # Connectivity probe: any URL that answers `check_expect_status` (and optionally
    # contains `check_expect_body`) when the internet is reachable.
    "check_url": "http://connectivitycheck.gstatic.com/generate_204",
    "check_expect_status": 204,
    "check_expect_body": "",
    "interval": 10,          # seconds between checks
    "idle_interval": 60,     # seconds between checks when outside `network_prefixes`
    "network_prefixes": [],  # optional: only act when the local IP starts with one of these
    "fail_backoff": 900,     # pause after a failed login, to avoid locking the account
    "timeout": 10,
    "max_steps": 4,          # portal pages to go through (terms page -> login page -> ...)
    # SECURITY: verified TLS is always tried first. Only when this is true, and only
    # after verification failed, the same request is retried without verification
    # (and credentials may be sent over plain HTTP if the portal offers nothing else).
    "allow_insecure_fallback": False,
    "captcha_command": "",   # external helper that answers captchas (see README)
    "field_map": {},         # {"username": "<input name>", "password": "<input name>"}
    "extra_fields": {},      # extra/override form fields, e.g. {"accept_terms": "1"}
    "login_url": "",         # force a login page/endpoint instead of auto-discovery
    "login_method": "POST",
    "logout_url": "",
    "user_agent": "Mozilla/5.0 (compatible; captive-autologin)",
}


def app_dir() -> Path:
    override = os.environ.get("CAPTIVE_AUTOLOGIN_HOME")
    if override:
        return Path(override)
    if SYSTEM == "Windows":
        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP
    return Path.home() / ("." + APP)


def config_file() -> Path:
    return app_dir() / "config.json"


def state_file() -> Path:
    return app_dir() / "state.json"


def log_file() -> Path:
    return app_dir() / "autologin.log"


def pid_file() -> Path:
    return app_dir() / "autologin.pid"


def load_json(path: Path, default: dict) -> dict:
    try:
        return {**default, **json.loads(path.read_text())}
    except (OSError, ValueError):
        return dict(default)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2))


def load_config() -> dict:
    return load_json(config_file(), DEFAULTS)
