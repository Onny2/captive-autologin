import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from captive_autologin import forms, portal  # noqa: E402
from captive_autologin.config import DEFAULTS  # noqa: E402
from fake_portal import CAPTCHA_TEXT, PASSWORD, USER, Portal  # noqa: E402


def make_cfg(p, **kw):
    cfg = dict(DEFAULTS, check_url=p.base + "/generate_204", allow_insecure_fallback=True, timeout=5)
    cfg.update(kw)
    return cfg


class Base(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        os.environ["CAPTIVE_AUTOLOGIN_HOME"] = self.home
        self.portals = []

    def tearDown(self):
        for p in self.portals:
            p.close()
        shutil.rmtree(self.home, ignore_errors=True)

    def portal(self, *a, **kw):
        p = Portal(*a, **kw)
        self.portals.append(p)
        return p


class FormEngine(Base):
    def test_login_with_csrf_hidden_fields_and_terms_checkbox(self):
        p = self.portal("form")
        r = portal.login(make_cfg(p), USER, PASSWORD)
        self.assertEqual(r.status, "logged_in", r)
        sent = p.posts[-1][1]
        self.assertNotIn("cancel", sent)       # picked "Log in", not "Cancel"
        self.assertNotIn("remember", sent)     # did not tick "remember me"
        self.assertEqual(sent["tos"], "yes")   # ticked the terms checkbox
        self.assertEqual(sent["redirect"], "http://example.com/")  # hidden field preserved

    def test_already_authenticated(self):
        p = self.portal("form")
        s = portal.new_session(make_cfg(p))
        self.assertEqual(portal.login(make_cfg(p), USER, PASSWORD, s).status, "logged_in")
        self.assertEqual(portal.login(make_cfg(p), USER, PASSWORD, s).status, "already")

    def test_wrong_password_fails_with_reason(self):
        p = self.portal("form")
        r = portal.login(make_cfg(p), USER, "wrong")
        self.assertEqual(r.status, "failed")
        self.assertIn("Login failed", r.detail)

    def test_click_through_portal_without_credentials(self):
        p = self.portal("click")
        r = portal.login(make_cfg(p), "", "")
        self.assertEqual(r.status, "logged_in", r)

    def test_meta_refresh_redirect_like_aruba(self):
        p = self.portal("meta")
        self.assertEqual(portal.login(make_cfg(p), USER, PASSWORD).status, "logged_in")

    def test_multi_step_terms_then_login(self):
        p = self.portal("steps")
        self.assertEqual(portal.login(make_cfg(p), USER, PASSWORD).status, "logged_in")
        self.assertEqual([path for path, _ in p.posts], ["/terms", "/login"])

    def test_extra_fields_and_field_map_overrides(self):
        page = forms.parse_page('<form action="/x" method="post"><input name="weird_id">'
                                '<input type="password" name="k"><input type="hidden" name="a" value="1">'
                                '<input type="submit" name="s" value="Go"></form>', "http://h/")
        form, mode = forms.choose_form(page)
        pairs, _ = forms.build_payload(form, "bob", "pw", {"field_map": {"username": "weird_id"},
                                                            "extra_fields": {"a": "2", "z": "9"}})
        self.assertEqual(dict(pairs), {"weird_id": "bob", "k": "pw", "a": "2", "s": "Go", "z": "9"})
        self.assertEqual(mode, "login")


class Captchas(Base):
    def test_recaptcha_is_detected_and_not_bypassed(self):
        p = self.portal("recaptcha")
        r = portal.login(make_cfg(p), USER, PASSWORD)
        self.assertEqual((r.status, r.detail), ("captcha", "recaptcha"))
        self.assertEqual(p.posts, [])  # nothing submitted without a valid token

    def test_recaptcha_token_from_external_command(self):
        p = self.portal("recaptcha")
        script = os.path.join(self.home, "solver.py")
        with open(script, "w") as f:
            f.write(textwrap.dedent("""
                import json, sys
                req = json.load(sys.stdin)
                assert req["kind"] == "recaptcha" and req["sitekey"] == "SITEKEY123", req
                print("tok")
            """))
        cfg = make_cfg(p, captcha_command=f'"{sys.executable}" "{script}"')
        self.assertEqual(portal.login(cfg, USER, PASSWORD).status, "logged_in")

    def test_image_captcha_answered_by_external_command(self):
        p = self.portal("image")
        script = os.path.join(self.home, "ocr.py")
        with open(script, "w") as f:
            f.write(textwrap.dedent(f"""
                import base64, json, sys
                req = json.load(sys.stdin)
                assert req["kind"] == "image" and req["field"] == "captcha"
                assert base64.b64decode(req["image_base64"]).startswith(b"\\x89PNG")
                print("{CAPTCHA_TEXT}")
            """))
        cfg = make_cfg(p, captcha_command=f'"{sys.executable}" "{script}"')
        self.assertEqual(portal.login(cfg, USER, PASSWORD).status, "logged_in")

    def test_failing_captcha_command_does_not_submit(self):
        p = self.portal("image")
        cfg = make_cfg(p, captcha_command=f'"{sys.executable}" -c "import sys; sys.exit(3)"')
        self.assertEqual(portal.login(cfg, USER, PASSWORD).status, "captcha")
        self.assertEqual(p.posts, [])


class TlsPolicy(Base):
    def _cert(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl not available")
        crt, key = os.path.join(self.home, "c.pem"), os.path.join(self.home, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt,
                        "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
                       check=True, capture_output=True)
        return crt, key

    def test_self_signed_portal_is_refused_by_default_and_nothing_is_sent(self):
        p = self.portal("form", use_tls=self._cert())
        r = portal.login(make_cfg(p, allow_insecure_fallback=False), USER, PASSWORD)
        self.assertEqual(r.status, "tls", r)
        self.assertEqual(p.posts, [])

    def test_self_signed_portal_works_with_the_fallback(self):
        p = self.portal("form", use_tls=self._cert())
        r = portal.login(make_cfg(p, allow_insecure_fallback=True), USER, PASSWORD)
        self.assertEqual(r.status, "logged_in", r)

    def test_plain_http_credentials_need_the_fallback(self):
        p = self.portal("form")
        r = portal.login(make_cfg(p, allow_insecure_fallback=False), USER, PASSWORD)
        self.assertEqual(r.status, "tls", r)
        self.assertEqual(p.posts, [])  # HTTPS upgrade failed, password never sent over HTTP
        self.assertEqual(portal.login(make_cfg(p), USER, PASSWORD).status, "logged_in")

    def test_click_through_over_http_needs_no_fallback(self):
        p = self.portal("click")
        r = portal.login(make_cfg(p, allow_insecure_fallback=False), "", "")
        self.assertEqual(r.status, "logged_in", r)

    def test_credentials_are_not_sent_to_another_host_over_http(self):
        p = self.portal("form")
        page = forms.parse_page('<form action="http://evil.example/login" method="post">'
                                '<input name="u"><input type="password" name="p"></form>', p.base + "/portal")
        form, _ = forms.choose_form(page)
        s = portal.new_session(make_cfg(p))
        with self.assertRaises(OSError):
            portal.submit(s, page, form, [("u", USER), ("p", PASSWORD)])


if __name__ == "__main__":
    unittest.main()
