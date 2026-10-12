"""Portal engine: detect the captive portal, fill its form, solve/skip captchas, submit.

Credential safety rules (the Wi-Fi is treated as hostile):
  1. HTTPS is always tried with full verification first.
  2. Unverified HTTPS / plain HTTP is used only if `allow_insecure_fallback` is true.
  3. Credentials are only sent to the host the form came from, unless the target is a
     different HTTPS host whose certificate verifies.
"""

from __future__ import annotations

import base64
import json
import logging
import shlex
import subprocess
import time
import webbrowser
from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from . import forms
from .config import SYSTEM, app_dir
from .net import Session, TLSError
from .util import open_path

log = logging.getLogger("captive-autologin")


class Result:
    """status: already | logged_in | failed | captcha | noform | nocreds | tls | offline | other"""

    def __init__(self, status, detail=""):
        self.status, self.detail = status, detail

    def __repr__(self):
        return f"Result({self.status!r}, {self.detail!r})"


def new_session(cfg) -> Session:
    return Session(allow_insecure=bool(cfg["allow_insecure_fallback"]),
                   timeout=cfg["timeout"], user_agent=cfg["user_agent"])


def _text_of(body):
    return forms.parse_page(body, "").text[:200]


# ------------------------------------------------------------------ probe

def probe(cfg, session):
    """Returns (kind, page): kind is ok | portal | offline | other | tls."""
    try:
        first = session.request(cfg["check_url"], timeout=6)
        if first.status == int(cfg["check_expect_status"]) and \
                (not cfg["check_expect_body"] or cfg["check_expect_body"] in first.body):
            return "ok", None
        final = session.follow(first)
    except TLSError:
        return "tls", None
    except OSError:
        return "offline", None
    if final.status == int(cfg["check_expect_status"]) and final is not first:
        return "ok", None
    page = forms.parse_page(final.body, final.url)
    if page.forms or final is not first:
        return "portal", page
    return "other", None


# ------------------------------------------------------------------ submit

def _csrf_headers(session, page):
    headers = {}
    for name, value in page.metas.items():
        if value:
            headers["X-CSRF-Token"] = value
    xsrf = session.cookie("XSRF-TOKEN")
    if xsrf:
        headers["X-XSRF-TOKEN"] = unquote(xsrf)
    csrf = session.cookie("csrftoken")
    if csrf:
        headers["X-CSRFToken"] = csrf
    parts = urlsplit(page.url)
    headers["Origin"] = f"{parts.scheme}://{parts.netloc}"
    headers["Referer"] = page.url
    return headers


def _candidates(session, page, url, secret):
    """URLs to try, in order, as (url, insecure_ok)."""
    target, origin = urlsplit(url), urlsplit(page.url)
    if not secret:
        return [(url, None)]
    if target.hostname != origin.hostname:
        # Never hand credentials to another host over anything but verified HTTPS.
        return [(url, False)] if target.scheme == "https" else []
    cands = []
    if target.scheme == "http":
        if target.port in (None, 80):  # secure attempt first: same URL over HTTPS
            cands.append((urlunsplit(target._replace(scheme="https", netloc=target.hostname)), None))
        if session.allow_insecure:
            cands.append((url, None))
    else:
        cands.append((url, None))
    return cands


def submit(session, page, form, pairs, method=None):
    method = (method or form.method).upper()
    secret = any(f.type == "password" for f in form.fields) or \
        any(n in ("password", "passwd", "pass", "pwd") for n, _ in pairs)
    headers = _csrf_headers(session, page)
    body = urlencode(pairs)
    cands = _candidates(session, page, form.action, secret)
    if not cands:
        raise TLSError("refusing to send credentials to a different host over plain HTTP")
    last = None
    for url, insecure_ok in cands:
        try:
            if method == "GET":
                sep = "&" if "?" in url else "?"
                resp = session.request(url + sep + body, headers=headers, insecure_ok=insecure_ok)
            else:
                resp = session.request(url, "POST", body.encode(), headers, insecure_ok=insecure_ok)
            return session.follow(resp)
        except OSError as e:
            last = e
            log.info("Attempt to %s failed: %s", urlsplit(url).scheme.upper(), e)
    if isinstance(last, TLSError):
        raise last
    if urlsplit(form.action).scheme == "http" and not session.allow_insecure:
        raise TLSError("the portal only accepts credentials over plain HTTP; nothing was sent. "
                       "To allow it on this network: captive-autologin config set "
                       "allow_insecure_fallback true")
    raise last


# ------------------------------------------------------------------ captcha

def _solve_captcha(cap, page, session, cfg, interactive):
    """Returns the answer/token, "" if solved manually in the browser, or None if unsolved."""
    image_b64 = ""
    if cap.kind == "image" and cap.image_url:
        try:
            raw = session.request(cap.image_url, headers={"Referer": page.url}).raw
            image_b64 = base64.b64encode(raw).decode()
            (app_dir() / "captcha.img").write_bytes(raw)
        except OSError as e:
            log.warning("Could not download the captcha image: %s", e)
    command = cfg.get("captcha_command")
    if command:
        payload = {"kind": cap.kind, "sitekey": cap.sitekey, "page_url": page.url,
                   "field": cap.field, "image_base64": image_b64,
                   "image_path": str(app_dir() / "captcha.img") if image_b64 else ""}
        try:
            r = subprocess.run(shlex.split(command, posix=SYSTEM != "Windows"), input=json.dumps(payload),
                               capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as e:
            log.error("captcha_command failed: %s", e)
            return None
        answer = r.stdout.strip()
        if r.returncode == 0 and answer:
            return answer
        log.error("captcha_command returned %s: %s", r.returncode, r.stderr.strip()[:200])
        return None
    if interactive:
        if cap.kind == "image" and image_b64:
            open_path(app_dir() / "captcha.img")
            return input("Captcha text: ").strip() or None
        print(f"This portal uses {cap.kind}. Opening it in your browser: complete it there.")
        webbrowser.open(page.url)
        input("Press Enter when you are connected... ")
        return ""
    return None


# ------------------------------------------------------------------ login

def _login_page(cfg, session, page):
    if cfg["login_url"]:
        resp = session.fetch(cfg["login_url"])
        return forms.parse_page(resp.body, resp.url)
    return page


def _synthetic_form(cfg, url):
    fm = cfg["field_map"]
    form = forms.Form(url, cfg["login_method"], {})
    user = forms.Field("input", "text", {"name": fm.get("username", "username")})
    pw = forms.Field("input", "password", {"name": fm.get("password", "password")})
    form.fields = [user, pw]
    return form


def login(cfg, user, password, session=None, interactive=False) -> Result:
    session = session or new_session(cfg)
    kind, page = probe(cfg, session)
    if kind == "ok":
        return Result("already")
    if kind != "portal":
        return Result(kind)
    detail = ""
    try:
        page = _login_page(cfg, session, page)
        for step in range(cfg["max_steps"]):
            form, mode = forms.choose_form(page)
            method = None
            if form is None and cfg["login_url"]:
                form, mode, method = _synthetic_form(cfg, cfg["login_url"]), "login", cfg["login_method"]
            if form is None:
                return Result("noform", page.text[:200])
            if mode == "login" and not (user and password):
                return Result("nocreds")
            pairs, unfilled = forms.build_payload(form, user, password, cfg)
            if unfilled:
                log.warning("Required fields left empty (set extra_fields): %s", ", ".join(unfilled))
            cap = forms.detect_captcha(page, form)
            if cap:
                answer = _solve_captcha(cap, page, session, cfg, interactive)
                if answer is None:
                    return Result("captcha", cap.kind)
                if answer:
                    pairs = [(n, v) for n, v in pairs if n != cap.field] + [(cap.field, answer)]
            log.info("Step %d: submitting %s form to %s (%d fields)", step + 1, mode, form.action, len(pairs))
            resp = submit(session, page, form, pairs, method)
            detail = _text_of(resp.body)
            time.sleep(1.5)
            kind, probe_page = probe(cfg, session)
            if kind == "ok":
                return Result("logged_in")
            nxt = forms.parse_page(resp.body, resp.url)
            page = nxt if nxt.forms else (probe_page or nxt)
    except TLSError as e:
        return Result("tls", str(e))
    except OSError as e:
        return Result("failed", str(e))
    return Result("failed", detail)


def logout(cfg, session=None):
    if not cfg["logout_url"]:
        return False
    session = session or new_session(cfg)
    resp = session.fetch(cfg["logout_url"])
    return resp.status < 400
