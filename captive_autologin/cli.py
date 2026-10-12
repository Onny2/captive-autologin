"""Command line interface."""

from __future__ import annotations

import getpass
import json
import logging
import logging.handlers
import os
import socket
import sys
import time

from . import __version__, forms, portal, secrets_store, service
from .config import (APP, DEFAULTS, app_dir, config_file, load_config, load_json, log_file, pid_file,
                     save_json, state_file)
from .util import notify

log = logging.getLogger(APP)

USAGE = f"""captive-autologin {__version__} - log in to captive Wi-Fi portals automatically

  install [--username U] [--password-stdin] [--reuse] [--insecure-fallback]
                       store credentials and start the background service
  uninstall            stop the service and delete the stored credentials
  status               are we online / behind a portal?
  login [--force] [--interactive]
                       log in now (--interactive lets you answer captchas yourself)
  inspect              show what the engine sees on the current portal (secrets masked)
  logout               log out (needs "logout_url" in the config)
  config [set KEY JSON]  show the config, or change one value
  run                  the service loop (started by the service itself)

Config file: {config_file()}
"""


def setup_logging():
    app_dir().mkdir(parents=True, exist_ok=True)
    log.setLevel(logging.INFO)
    fh = logging.handlers.RotatingFileHandler(log_file(), maxBytes=1_000_000, backupCount=1, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    log.addHandler(fh)
    if sys.stdout and sys.stdout.isatty():
        log.addHandler(logging.StreamHandler(sys.stdout))


# ------------------------------------------------------------------ network helpers

def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))  # UDP connect sends nothing
            return s.getsockname()[0]
    except OSError:
        return None


def on_network(cfg):
    prefixes = cfg["network_prefixes"]
    if not prefixes:
        return True
    ip = local_ip()
    return ip is not None and any(ip.startswith(p) for p in prefixes)


# ------------------------------------------------------------------ login with backoff

def check_and_login(cfg, force=False, interactive=False):
    state = load_json(state_file(), {"last_failure": 0})
    session = portal.new_session(cfg)
    kind, _ = portal.probe(cfg, session)
    if kind == "ok":
        return portal.Result("already")
    if kind == "portal" and not force and time.time() - state["last_failure"] < cfg["fail_backoff"]:
        return portal.Result("backoff")
    if kind not in ("portal",):
        return portal.Result(kind)
    log.info("Captive portal detected, trying to log in...")
    result = portal.login(cfg, cfg["username"], secrets_store.load(), session, interactive)
    if result.status == "logged_in":
        log.info("Login succeeded as %s", cfg["username"])
    else:
        log.error("Login failed (%s) %s", result.status, result.detail)
        if result.status == "captcha":
            notify("Captive portal needs a captcha",
                   f"{result.detail}: run `captive-autologin login --interactive` or set captcha_command")
    ok = result.status == "logged_in"
    state["last_failure"] = 0 if ok else time.time()
    save_json(state_file(), state)
    return result


# ------------------------------------------------------------------ commands

def cmd_install(args):
    cfg = load_config()
    if "--username" in args:
        cfg["username"] = args[args.index("--username") + 1]
    reuse_user = secrets_store.stored_user() or cfg["username"]
    if "--reuse" in args and reuse_user and secrets_store.load():
        user = reuse_user
        print(f"Reusing stored credentials for {user}")
    else:
        user = cfg["username"] if "--username" in args else input("Portal username: ").strip()
        if "--password-stdin" in args:
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass("Password: ")
            if password != getpass.getpass("Repeat password: "):
                sys.exit("Passwords do not match.")
        if not user or not password:
            sys.exit("Username and password are required.")
        if secrets_store.save(user, password) == "file":
            print(f"Note: no keyring available, password stored in {secrets_store.fallback_file()} (mode 600)")
    cfg["username"] = user
    if "--insecure-fallback" in args:
        cfg["allow_insecure_fallback"] = True
        print("WARNING: insecure fallback enabled - if TLS verification fails the password may be sent "
              "to an unverified server or over plain HTTP.")
    save_json(config_file(), {k: v for k, v in cfg.items() if v != DEFAULTS.get(k) or k == "username"})
    save_json(state_file(), {"last_failure": 0})
    print("Service enabled:", service.install_service())
    print("Log:", log_file())
    if not cfg["allow_insecure_fallback"]:
        print("If your portal uses a self-signed certificate: captive-autologin config set "
              "allow_insecure_fallback true")


def cmd_uninstall(_):
    service.uninstall_service()
    secrets_store.delete()
    print("Auto-login disabled and credentials removed.")


MESSAGES = {
    "ok": "Online",
    "already": "Already authenticated",
    "portal": "Not authenticated: captive portal detected",
    "backoff": "Paused after a failed login (use --force)",
    "offline": "Offline",
    "other": "Unknown network response (no captive portal recognised)",
    "tls": "Portal certificate could not be verified. To trust this network: "
           "captive-autologin config set allow_insecure_fallback true",
    "nocreds": "No credentials stored: run install",
    "noform": "A portal was found but no usable form (try `inspect`; maybe set login_url/extra_fields)",
    "captcha": "The portal asks for a captcha (use --interactive or captcha_command)",
    "failed": "Login failed",
    "logged_in": "Logged in",
}


def cmd_status(_):
    cfg = load_config()
    kind, _page = portal.probe(cfg, portal.new_session(cfg))
    print(MESSAGES[kind])


def cmd_login(args):
    result = check_and_login(load_config(), force="--force" in args, interactive="--interactive" in args)
    print(MESSAGES.get(result.status, result.status), result.detail if result.status == "failed" else "")
    sys.exit(1 if result.status in ("failed", "tls", "captcha", "noform", "nocreds") else 0)


def cmd_inspect(_):
    cfg = load_config()
    session = portal.new_session(cfg)
    kind, page = portal.probe(cfg, session)
    print("probe:", kind)
    if kind != "portal":
        return print(MESSAGES[kind])
    page = portal._login_page(cfg, session, page)
    print("portal page:", page.url)
    form, mode = forms.choose_form(page)
    if form is None:
        return print("no usable form found; forms on page:", len(page.forms))
    pairs, unfilled = forms.build_payload(form, "<username>", "<password>", cfg)
    print(f"form: {mode} -> {form.method} {form.action}")
    for name, value in pairs:
        masked = value if value in ("<username>", "<password>") else (value[:6] + "..." if len(value) > 9 else value)
        print(f"  {name} = {masked}")
    if unfilled:
        print("required but empty:", ", ".join(unfilled))
    print("captcha:", forms.detect_captcha(page, form) or "none")
    print("csrf meta:", ", ".join(page.metas) or "none")


def cmd_logout(_):
    cfg = load_config()
    print("Logged out" if portal.logout(cfg) else 'Logout failed or no "logout_url" configured')


def cmd_config(args):
    if args[:1] == ["set"] and len(args) == 3:
        cfg = load_json(config_file(), {})
        key = args[1]
        if key not in DEFAULTS:
            sys.exit(f"Unknown key {key!r}. Known: {', '.join(DEFAULTS)}")
        try:
            cfg[key] = json.loads(args[2])
        except ValueError:
            cfg[key] = args[2]
        save_json(config_file(), cfg)
        print(f"{key} = {cfg[key]!r}")
        if key == "allow_insecure_fallback" and cfg[key]:
            print("WARNING: credentials may now be sent over unverified TLS / plain HTTP as a last resort.")
        return
    print(config_file())
    print(json.dumps(load_config(), indent=2))


def cmd_run(_):
    pid_file().parent.mkdir(parents=True, exist_ok=True)
    pid_file().write_text(str(os.getpid()))
    log.info("Service started (pid %s)", os.getpid())
    active = None
    next_probe = 0
    while True:
        cfg = load_config()
        if on_network(cfg):
            if active is not True:
                log.info("Watching the network every %ss", cfg["interval"])
                active = True
            due, pause = True, cfg["interval"]
        else:
            if active is not False:
                log.info("Not on a configured network: checks reduced")
                active, next_probe = False, time.time() + cfg["idle_interval"]
            due, pause = time.time() >= next_probe, 5
            if due:
                next_probe = time.time() + cfg["idle_interval"]
        if due:
            try:
                check_and_login(cfg)
            except Exception:
                log.exception("Unexpected error")
        time.sleep(pause)


COMMANDS = {"install": cmd_install, "uninstall": cmd_uninstall, "status": cmd_status, "login": cmd_login,
            "inspect": cmd_inspect, "logout": cmd_logout, "config": cmd_config, "run": cmd_run}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    wizard = not argv and service.frozen()  # double-clicked .exe / .dmg binary
    if wizard:
        argv = ["install"]
    elif not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0
    elif argv[0] in ("-V", "--version"):
        print(__version__)
        return 0
    if argv[0] not in COMMANDS:
        print(USAGE)
        return 2
    setup_logging()
    try:
        COMMANDS[argv[0]](argv[1:])
    except SystemExit as e:
        if isinstance(e.code, str):
            print(e.code, file=sys.stderr)
        if wizard:
            input("Press Enter to close...")
        return e.code if isinstance(e.code, int) else (1 if e.code else 0)
    if wizard:
        input("Press Enter to close...")
    return 0
