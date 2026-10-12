"""A configurable fake captive portal used by the tests."""

import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

USER, PASSWORD, CAPTCHA_TEXT = "alice", "s3cret", "XK42"

FORM = """<html><body>
<form action="/search" method="get"><input name="q" type="text"><input type="submit" value="Search"></form>
{extra}
<form action="/login" method="post" id="loginform">
 <input type="hidden" name="csrf" value="{token}">
 <input type="hidden" name="redirect" value="http://example.com/">
 <label for="u">Username</label><input type="text" id="u" name="u">
 <label for="p">Password</label><input type="password" id="p" name="p">
 {captcha}
 <label><input type="checkbox" name="remember" value="1"> Remember me</label>
 <label for="t"><input type="checkbox" id="t" name="tos" value="yes"> I accept the terms and conditions</label>
 <input type="submit" name="cancel" value="Cancel"><input type="submit" name="go" value="Log in">
</form></body></html>"""

CLICK = """<html><body><form action="/accept" method="post">
<input type="hidden" name="session" value="{token}">
<label><input type="checkbox" name="agree" value="1"> I agree to the usage policy</label>
<button type="submit" name="btn" value="connect">Connect</button></form></body></html>"""


class Portal:
    def __init__(self, mode="form", use_tls=False):
        self.mode = mode  # form | click | meta | recaptcha | image | steps
        self.tokens, self.authed, self.posts = {}, set(), []
        self.stage = {}  # sid -> step reached (mode "steps")
        self.httpd = HTTPServer(("127.0.0.1", 0), self._handler())
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(use_tls[0], use_tls[1])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        port = self.httpd.server_address[1]
        self.base = f"{'https' if use_tls else 'http'}://127.0.0.1:{port}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _handler(self):
        portal = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def sid(self):
                for part in self.headers.get("Cookie", "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == "sid":
                        return v
                return None

            def send(self, status, body="", headers=None):
                data = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "text/html" if isinstance(body, str) else "image/png")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urlsplit(self.path).path
                sid = self.sid()
                if path == "/generate_204":
                    if sid in portal.authed:
                        return self.send(204)
                    if portal.mode == "meta":
                        return self.send(200, f'<html><head><meta http-equiv="refresh" content="0;url={portal.base}'
                                              f'/portal"></head></html>')
                    return self.send(302, headers={"Location": portal.base + "/portal"})
                if path == "/cap.png":
                    return self.send(200, b"\x89PNG fake")
                if path == "/portal":
                    sid = sid or secrets.token_hex(8)
                    token = portal.tokens.setdefault(sid, secrets.token_hex(8))
                    hdr = {"Set-Cookie": f"sid={sid}; Path=/"}
                    if portal.mode == "click":
                        return self.send(200, CLICK.format(token=token), hdr)
                    if portal.mode == "steps" and portal.stage.get(sid) != "terms":
                        return self.send(200, CLICK.format(token=token).replace("/accept", "/terms"), hdr)
                    captcha = {"recaptcha": '<div class="g-recaptcha" data-sitekey="SITEKEY123"></div>'
                                            '<script src="https://www.google.com/recaptcha/api.js"></script>',
                               "image": '<img src="/cap.png" alt="captcha"><input type="text" name="captcha">',
                               }.get(portal.mode, "")
                    return self.send(200, FORM.format(token=token, captcha=captcha, extra=""), hdr)
                self.send(404, "nope")

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode(), keep_blank_values=True).items()}
                sid = self.sid()
                path = urlsplit(self.path).path
                portal.posts.append((path, form))
                if path == "/terms" and form.get("agree") and form.get("session") == portal.tokens.get(sid):
                    portal.stage[sid] = "terms"
                    return self.send(302, headers={"Location": portal.base + "/portal"})
                if path == "/accept" and form.get("agree") and form.get("session") == portal.tokens.get(sid):
                    portal.authed.add(sid)
                    return self.send(200, "Connected")
                ok = (path == "/login" and sid in portal.tokens and form.get("csrf") == portal.tokens[sid]
                      and form.get("tos") == "yes" and form.get("go") and "cancel" not in form
                      and form.get("u") == USER and form.get("p") == PASSWORD
                      and (portal.mode != "recaptcha" or form.get("g-recaptcha-response") == "tok")
                      and (portal.mode != "image" or form.get("captcha") == CAPTCHA_TEXT))
                if ok:
                    portal.authed.add(sid)
                    return self.send(200, "Authentication successful")
                self.send(200, "<html><body><h1>Login failed</h1><p>Bad credentials or token</p></body></html>")

        return H
