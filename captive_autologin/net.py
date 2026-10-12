"""HTTP session: cookies, manual redirects (HTTP / meta refresh / JS) and the TLS policy.

TLS policy: every HTTPS request is first made with full certificate verification.
Only if that fails *because of the certificate* and `allow_insecure_fallback` is on,
the request is retried without verification. A failed verification aborts the
handshake, so no request body (credentials) ever reaches an unverified peer unless
the fallback is explicitly enabled.
"""

from __future__ import annotations

import logging
import os
import ssl
import urllib.error
import urllib.request
from http.cookiejar import CookieJar
from urllib.parse import urljoin, urlsplit

from . import forms
from .config import SYSTEM

log = logging.getLogger("captive-autologin")

MAX_BODY = 1 << 20
REDIRECTS = (301, 302, 303, 307, 308)


class TLSError(OSError):
    """Certificate verification failed and the insecure fallback is not enabled."""


class Response:
    def __init__(self, status, url, headers, raw):
        self.status = status
        self.url = url
        self.headers = headers
        self.raw = raw
        charset = "utf-8"
        ctype = headers.get("content-type", "")
        if "charset=" in ctype:
            charset = ctype.split("charset=")[1].split(";")[0].strip().strip('"\'') or charset
        try:
            self.body = raw.decode(charset, "replace")
        except LookupError:
            self.body = raw.decode("utf-8", "replace")
        loc = headers.get("location")
        self.location = urljoin(url, loc) if loc else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _verified_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    # Bundled (frozen) Python on macOS ships without CA certificates: use the system file.
    if SYSTEM == "Darwin" and ctx.cert_store_stats().get("x509_ca", 0) == 0:
        for cafile in ("/etc/ssl/cert.pem",):
            if os.path.exists(cafile):
                ctx.load_verify_locations(cafile)
    return ctx


def _is_cert_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", exc)
    return isinstance(reason, ssl.SSLCertVerificationError)


class Session:
    def __init__(self, allow_insecure=False, timeout=10, user_agent="captive-autologin"):
        self.jar = CookieJar()
        self.allow_insecure = allow_insecure
        self.timeout = timeout
        self.user_agent = user_agent
        self.insecure_hosts = set()  # hosts that needed the fallback in this session
        self._openers = {}

    def _opener(self, insecure):
        if insecure not in self._openers:
            ctx = ssl._create_unverified_context() if insecure else _verified_context()
            self._openers[insecure] = urllib.request.build_opener(
                _NoRedirect, urllib.request.HTTPCookieProcessor(self.jar),
                urllib.request.HTTPSHandler(context=ctx))
        return self._openers[insecure]

    def _do(self, url, method, data, headers, insecure, timeout):
        h = {"User-Agent": self.user_agent, "Accept": "text/html,*/*;q=0.8"}
        h.update(headers or {})
        if data is not None:
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            resp = self._opener(insecure).open(req, timeout=timeout or self.timeout)
        except urllib.error.HTTPError as e:  # 3xx (no-redirect), 4xx, 5xx are still responses
            resp = e
        try:
            raw = resp.read(MAX_BODY)
            status = getattr(resp, "status", None) or resp.code
            headers_out = {k.lower(): v for k, v in resp.headers.items()}
            return Response(status, resp.geturl() or url, headers_out, raw)
        finally:
            resp.close()

    def request(self, url, method="GET", data=None, headers=None, timeout=None, insecure_ok=None):
        """`insecure_ok` overrides the session-wide fallback permission for this request."""
        allowed = self.allow_insecure if insecure_ok is None else insecure_ok
        parts = urlsplit(url)
        is_https = parts.scheme.lower() == "https"
        insecure = is_https and allowed and parts.hostname in self.insecure_hosts
        try:
            return self._do(url, method, data, headers, insecure, timeout)
        except urllib.error.URLError as e:
            if not (is_https and not insecure and _is_cert_error(e)):
                raise
            reason = getattr(e.reason, "verify_message", None) or str(e.reason)
            if not allowed:
                raise TLSError(
                    f"TLS certificate of {parts.hostname} could not be verified ({reason}). "
                    "Nothing was sent. If you trust this network, enable the fallback: "
                    "captive-autologin config set allow_insecure_fallback true") from e
            log.warning("TLS verification failed for %s (%s): retrying WITHOUT verification "
                        "(allow_insecure_fallback)", parts.hostname, reason)
            self.insecure_hosts.add(parts.hostname)
            return self._do(url, method, data, headers, True, timeout)

    def follow(self, resp, hops=8):
        """Follow HTTP, <meta refresh> and JavaScript redirects starting from `resp`."""
        for _ in range(hops):
            nxt = None
            if resp.status in REDIRECTS and resp.location:
                nxt = resp.location
            elif resp.body:
                nxt = forms.find_redirect(forms.parse_page(resp.body, resp.url))
            if not nxt or nxt == resp.url:
                return resp
            resp = self.request(nxt, headers={"Referer": resp.url})
        return resp

    def fetch(self, url, **kw):
        return self.follow(self.request(url, **kw))

    def cookie(self, name):
        for c in self.jar:
            if c.name == name:
                return c.value
        return None
