"""Understanding portal pages: forms, hidden/CSRF fields, terms checkboxes, redirects, captchas.

Nothing here is vendor specific: it works from the HTML structure and common naming.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

TEXTLIKE = {"text", "email", "tel", "number", "search", "url", ""}
NON_DATA = {"submit", "button", "image", "reset", "file"}

TERMS_RE = re.compile(
    r"accept|agree|terms|\btos\b|condition|condizion|termin|accett|policy|privacy|consent|"
    r"acknowledg|autorizz|acepto|aceptar|akzeptier|einverstanden|j.accepte|\bcgu\b|\bcgv\b", re.I)
REMEMBER_RE = re.compile(r"remember|keep me|stay signed|ricorda|mantieni|persist", re.I)
USER_RE = re.compile(r"user|login|e-?mail|account|matric|utente|ident|badge|member|\bid\b|name|phone|mobile", re.I)
SUBMIT_GOOD = re.compile(r"log ?in|sign ?in|connect|continue|accept|submit|accedi|entra|connetti|avanti|"
                         r"continua|accetto|conferma|proceed|agree|enter|start|authenticate|next|\bok\b", re.I)
SUBMIT_BAD = re.compile(r"cancel|decline|reject|back|annulla|rifiut|indietro|refuse|deny|log ?out|"
                        r"register|sign ?up|forgot", re.I)
BAD_FORM_RE = re.compile(r"search|newsletter|subscribe|register|signup|sign-up|forgot|reset|language|lang", re.I)
CAPTCHA_INPUT_RE = re.compile(r"captcha|security.?code|verification.?code|verify.?code|codice.?(di)?.?"
                              r"(sicurezza|verifica)|anti.?bot", re.I)
JS_REDIRECT_RE = re.compile(
    r"""(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*(?:=|\.replace\(|\.assign\()\s*['"]([^'"]+)['"]""")


class Field:
    def __init__(self, tag, ftype, attrs):
        self.tag = tag
        self.type = ftype
        self.name = attrs.get("name", "")
        self.id = attrs.get("id", "")
        self.value = attrs.get("value", "")
        self.checked = "checked" in attrs
        self.required = "required" in attrs
        self.disabled = "disabled" in attrs
        self.hint = " ".join(attrs.get(k, "") for k in ("placeholder", "aria-label", "title"))
        self.label = ""
        self.options = []

    @property
    def hay(self):
        parts = [self.name, self.id, self.label, self.hint]
        if self.type in ("checkbox", "radio"):
            parts.append(self.value)
        return " ".join(parts).lower()


class Form:
    def __init__(self, action, method, attrs):
        self.action = action
        self.method = (method or "GET").upper()
        self.id = attrs.get("id", "") + " " + attrs.get("name", "")
        self.fields = []


class Captcha:
    def __init__(self, kind, sitekey="", field="", image_url=""):
        self.kind, self.sitekey, self.field, self.image_url = kind, sitekey, field, image_url

    def __repr__(self):
        return f"Captcha({self.kind})"


class Page:
    def __init__(self, url, raw):
        self.url = url
        self.raw = raw
        self.forms = []
        self.meta_refresh = None
        self.metas = {}
        self.imgs = []
        self.scripts = []
        self.iframes = []
        self.marks = []
        self.script_text = ""
        self.text = ""


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.cur = [], None
        self.base = None
        self.meta_refresh, self.metas = None, {}
        self.label_for, self.label_stack = {}, []
        self.imgs, self.scripts, self.iframes, self.marks = [], [], [], []
        self.script_text, self.text = [], []
        self._in = None
        self._btn = self._sel = self._opt = None

    def _add(self, field):
        if self.cur is not None:
            self.cur.fields.append(field)
        if self.label_stack:
            self.label_stack[-1]["fields"].append(field)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        cls = a.get("class", "").lower()
        if "data-sitekey" in a or "captcha" in cls or "captcha" in a.get("id", "").lower():
            self.marks.append((tag, a))
        if tag == "base" and a.get("href"):
            self.base = a["href"]
        elif tag == "meta":
            name = a.get("name", "").lower()
            if a.get("http-equiv", "").lower() == "refresh":
                m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
                if m:
                    self.meta_refresh = m.group(1).strip()
            elif "csrf" in name or "xsrf" in name:
                self.metas[name] = a.get("content", "")
        elif tag == "form":
            self.cur = Form(a.get("action", ""), a.get("method", "GET"), a)
            self.forms.append(self.cur)
        elif tag == "label":
            self.label_stack.append({"for": a.get("for"), "text": [], "fields": []})
        elif tag == "input":
            self._add(Field("input", a.get("type", "text").lower(), a))
        elif tag == "button":
            self._btn = Field("button", a.get("type", "submit").lower(), a)
            self._add(self._btn)
        elif tag == "select":
            self._sel = Field("select", "select", a)
            self._add(self._sel)
        elif tag == "option" and self._sel is not None:
            self._opt = {"value": a.get("value") if "value" in a else None,
                         "selected": "selected" in a, "text": []}
        elif tag == "textarea":
            self._add(Field("textarea", "textarea", a))
            self._in = "textarea"
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "iframe":
            self.iframes.append(a.get("src", ""))
        elif tag in ("script", "style"):
            self._in = tag
            if tag == "script" and a.get("src"):
                self.scripts.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None
        elif tag == "label" and self.label_stack:
            lab = self.label_stack.pop()
            text = " ".join(t for t in lab["text"] if t).strip()
            if lab["for"]:
                self.label_for[lab["for"]] = text
            for f in lab["fields"]:
                f.label = (f.label + " " + text).strip()
        elif tag == "button":
            self._btn = None
        elif tag == "option" and self._opt is not None:
            text = "".join(self._opt["text"]).strip()
            value = self._opt["value"] if self._opt["value"] is not None else text
            self._sel.options.append((value, self._opt["selected"]))
            self._opt = None
        elif tag == "select" and self._sel is not None:
            chosen = next((v for v, s in self._sel.options if s), None)
            if chosen is None and self._sel.options:
                chosen = self._sel.options[0][0]
            self._sel.value = chosen or ""
            self._sel = None
        elif tag in ("script", "style", "textarea"):
            self._in = None

    def handle_data(self, data):
        if self._in == "script":
            self.script_text.append(data)
            return
        if self._in in ("style", "textarea"):
            return
        if self._opt is not None:
            self._opt["text"].append(data)
        if self._btn is not None:
            self._btn.label = (self._btn.label + " " + data.strip()).strip()
        for lab in self.label_stack:
            lab["text"].append(data.strip())
        self.text.append(data)


def parse_page(html, url) -> Page:
    p = _Parser()
    try:
        p.feed(html)
        p.close()
    except Exception:  # malformed markup must never kill the service
        pass
    page = Page(url, html)
    base = urljoin(url, p.base) if p.base else url
    for form in p.forms:
        form.action = urljoin(base, form.action) if form.action else url
        for f in form.fields:
            if f.id in p.label_for:
                f.label = (f.label + " " + p.label_for[f.id]).strip()
            if f.tag == "button":  # a <button>'s text is its caption
                f.hint = (f.hint + " " + f.label).strip()
    page.forms = p.forms
    page.meta_refresh = urljoin(base, p.meta_refresh) if p.meta_refresh else None
    page.metas, page.imgs, page.scripts = p.metas, p.imgs, p.scripts
    page.iframes, page.marks = p.iframes, p.marks
    page.script_text = "\n".join(p.script_text)
    page.text = re.sub(r"\s+", " ", " ".join(p.text)).strip()
    page.base = base
    return page


def find_redirect(page: Page):
    """Next URL if the page is only a redirect (meta refresh or JavaScript)."""
    if page.meta_refresh:
        return page.meta_refresh
    if page.forms:
        return None
    m = JS_REDIRECT_RE.search(page.script_text) or JS_REDIRECT_RE.search(page.raw)
    if m and not m.group(1).lower().startswith(("javascript:", "#")):
        return urljoin(page.base, m.group(1))
    return None


# ------------------------------------------------------------------ form choice / filling

def _is_terms(f):
    return f.type in ("checkbox", "radio") and bool(TERMS_RE.search(f.hay)) and not REMEMBER_RE.search(f.hay)


def _score(form):
    pw = [f for f in form.fields if f.type == "password" and not f.disabled]
    score = 0
    if len(pw) == 1:
        score += 10
    elif len(pw) > 1:
        score += 2  # register / change-password forms
    if any(_is_terms(f) for f in form.fields):
        score += 4
    if any(f.type in ("submit", "image") or (f.tag == "button" and f.type != "button") for f in form.fields):
        score += 2
    if any(f.type == "file" for f in form.fields):
        score -= 5
    if BAD_FORM_RE.search(form.action + " " + form.id):
        score -= 3
    return score


def choose_form(page: Page):
    """Returns (form, "login"|"accept") or (None, None)."""
    best = max(page.forms, key=_score, default=None)
    if best is None or _score(best) < 2:
        return None, None
    has_pw = any(f.type == "password" for f in best.fields)
    return best, ("login" if has_pw else "accept")


def _pick_user_field(form, field_map):
    texts = [f for f in form.fields if f.type in TEXTLIKE and f.name and not f.disabled
             and f.tag == "input" and not CAPTCHA_INPUT_RE.search(f.hay)]
    if field_map.get("username"):
        return next((f for f in texts if f.name == field_map["username"]), None)
    return next((f for f in texts if USER_RE.search(f.hay)), texts[0] if texts else None)


def _pick_submit(form):
    buttons = [f for f in form.fields if f.name and not f.disabled
               and (f.type in ("submit", "image") or (f.tag == "button" and f.type == "submit"))]
    caption = lambda f: f.value + " " + f.hint + " " + f.label  # noqa: E731
    good = [b for b in buttons if not SUBMIT_BAD.search(caption(b))]
    for b in good:
        if SUBMIT_GOOD.search(caption(b)):
            return b
    return good[0] if good else None


def build_payload(form, user, password, cfg):
    """Ordered (name, value) pairs a browser would send. Returns (pairs, unfilled_required)."""
    field_map = cfg.get("field_map") or {}
    extra = dict(cfg.get("extra_fields") or {})
    user_field = _pick_user_field(form, field_map)
    pairs, unfilled, radios = [], [], {}
    for f in form.fields:
        if f.disabled or not f.name or f.type in NON_DATA:
            continue
        if f.name in extra:
            if f.type == "checkbox" and str(extra[f.name]).lower() in ("0", "false", "no", ""):
                continue
            pairs.append((f.name, str(extra[f.name])))
        elif f.type == "password":
            pairs.append((f.name, password))
        elif f is user_field:
            pairs.append((f.name, user))
        elif f.type == "checkbox":
            if _is_terms(f) or f.required or f.checked:
                pairs.append((f.name, f.value or "on"))
        elif f.type == "radio":
            radios.setdefault(f.name, []).append(f)
        elif f.type == "hidden" or f.tag in ("select", "textarea") or f.type in TEXTLIKE:
            if f.type in TEXTLIKE and f.tag == "input" and not f.value and f.required \
                    and not CAPTCHA_INPUT_RE.search(f.hay):
                unfilled.append(f.name)
            pairs.append((f.name, f.value))
        else:  # color/date/range... keep whatever the page pre-filled
            pairs.append((f.name, f.value))
    for name, group in radios.items():
        pick = next((r for r in group if r.checked), None) or next((r for r in group if _is_terms(r)), None)
        if pick:
            pairs.append((name, pick.value))
    submit = _pick_submit(form)
    if submit:
        pairs.append((submit.name, submit.value or submit.label))
    for k, v in extra.items():  # explicit extras the form did not declare
        if not any(n == k for n, _ in pairs):
            pairs.append((k, str(v)))
    return pairs, unfilled


# ------------------------------------------------------------------ captcha detection

_TOKEN_CAPTCHAS = (
    ("recaptcha", ("g-recaptcha", "google.com/recaptcha", "recaptcha/api", "recaptcha/enterprise"),
     "g-recaptcha-response"),
    ("hcaptcha", ("h-captcha", "hcaptcha.com"), "h-captcha-response"),
    ("turnstile", ("cf-turnstile", "challenges.cloudflare.com/turnstile"), "cf-turnstile-response"),
)


def detect_captcha(page: Page, form=None):
    low = page.raw.lower()
    for kind, markers, field in _TOKEN_CAPTCHAS:
        if any(m in low for m in markers):
            key = next((a["data-sitekey"] for _, a in page.marks if a.get("data-sitekey")), "")
            if not key:
                m = re.search(r"""sitekey["']?\s*[:=]\s*["']([\w-]+)""", page.raw, re.I)
                key = m.group(1) if m else ""
            return Captcha(kind, sitekey=key, field=field)
    candidates = form.fields if form is not None else []
    inp = next((f for f in candidates if f.type in TEXTLIKE and f.tag == "input"
                and CAPTCHA_INPUT_RE.search(f.hay)), None)
    if inp is None:
        return None
    img = next((i for i in page.imgs
                if re.search(r"captcha|securimage|seccode|verify", " ".join(
                    i.get(k, "") for k in ("src", "id", "alt", "class", "name")), re.I)), None)
    return Captcha("image", field=inp.name,
                   image_url=urljoin(page.base, img["src"]) if img and img.get("src") else "")
