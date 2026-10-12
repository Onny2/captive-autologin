# captive-autologin

Logs you in to captive Wi-Fi portals (university, hotel, office, airport...) automatically and keeps you connected. It works from the structure of the portal page rather than from a vendor script, so it is not tied to any one network. Python standard library only; ships as a `.deb`, a `.dmg` and a `.exe`.

[Italiano](README.it.md)

> ## ⚠️ Security: how credentials are sent
>
> A captive-portal Wi-Fi is a local, untrusted network, and many portals use self-signed certificates or plain HTTP. captive-autologin therefore **always tries the secure way first**:
>
> 1. **Secure attempt (always):** HTTPS with full certificate verification. A plain-HTTP login form is first retried over verified HTTPS. If verification fails, the handshake is aborted and **nothing is sent**.
> 2. **Insecure fallback (opt-in, off by default):** only if you enable `allow_insecure_fallback`, and only after step 1 failed, the same request is retried **without certificate verification**, or over plain HTTP when the portal offers nothing else. Anyone on that network could capture the password.
>
> Enable it only on a network you accept that risk for:
>
> ```sh
> captive-autologin config set allow_insecure_fallback true   # or: captive-autologin install --insecure-fallback
> captive-autologin config set allow_insecure_fallback false  # turn it off again
> ```
>
> Even with the fallback on, credentials are never sent to a *different* host than the one that served the form, unless that host has a valid HTTPS certificate. Portals that only ask you to accept terms (no password) work without the fallback.

## What it handles

| Portal feature | Support |
|---|---|
| HTTP, `<meta refresh>` and JavaScript redirects (Aruba, Cisco, UniFi, MikroTik, pfSense, CoovaChilli...) | yes |
| Hidden form fields and **CSRF tokens** (hidden inputs, `<meta name="csrf-token">`, `XSRF-TOKEN` / `csrftoken` cookies) | yes, re-read from a fresh page every attempt |
| **Terms / "I accept" checkboxes and radios** (EN/IT/ES/DE/FR wording); "remember me" is left alone | yes |
| Click-through portals with no password | yes |
| Multi-step portals (accept terms, then log in) | yes, up to `max_steps` pages |
| Unusual field names | `field_map`, `extra_fields` |
| JS-only portals (login done by `fetch()`) | set `login_url` + `field_map` + `extra_fields` from the request seen in your browser's dev tools |
| **Captchas** (reCAPTCHA, hCaptcha, Cloudflare Turnstile, image captchas) | detected; see below |

### Captchas

Captchas exist to tell humans from bots, so captive-autologin ships **no solver** and never submits a form that has an unanswered captcha. When one is detected it stops, backs off, and shows a desktop notification. You can answer it in two ways:

- **Yourself:** `captive-autologin login --interactive` shows an image captcha and asks for the text, or opens the portal in your browser for reCAPTCHA/hCaptcha/Turnstile.
- **A helper you provide:** set `captcha_command` to any program. It receives JSON on stdin and must print the answer (image text, or the token for token captchas) on stdout:

```json
{"kind": "recaptcha|hcaptcha|turnstile|image", "sitekey": "...", "page_url": "...",
 "field": "g-recaptcha-response", "image_base64": "...", "image_path": "..."}
```

Use this only on networks where you are entitled to log in.

## Install

Download from the [Releases](../../releases) page:

- **Linux (Debian/Ubuntu):** `sudo apt install ./captive-autologin_*_all.deb` then `captive-autologin install`
- **macOS:** open the `.dmg`, double-click `Install.command` (unsigned: right-click → Open the first time)
- **Windows:** run `captive-autologin-windows-x64.exe` and follow the prompts (SmartScreen may warn: the binary is unsigned)
- **Any OS with Python ≥ 3.9:** `pip install .` then `captive-autologin install`

`install` stores the password in the Keychain / Credential Manager / `secret-tool` (or a mode-600 file on Linux without a keyring) and starts a background service (launchd, Startup folder, systemd `--user` or desktop autostart). Remote or headless provisioning:

```sh
printf '%s\n' "$PASSWORD" | captive-autologin install --username me --password-stdin
loginctl enable-linger "$USER"    # Linux: start the service at boot without a login session
```

## Commands

```
install [--username U] [--password-stdin] [--reuse] [--insecure-fallback]
uninstall            stop the service, delete credentials
status               online / behind a portal?
login [--force] [--interactive]
inspect              show the form, fields (secrets masked) and captcha the engine sees
logout               needs "logout_url"
config [set KEY JSON]
run                  service loop
```

Logs and config live in `~/.captive-autologin` (`%LOCALAPPDATA%\captive-autologin` on Windows). If a portal does not work, run `captive-autologin inspect` and attach its output to an issue.

## Config

`captive-autologin config` prints the file. Keys: `check_url` / `check_expect_status` / `check_expect_body` (connectivity probe), `interval`, `network_prefixes` (only act on these IP ranges, e.g. `["10.20."]`), `fail_backoff` (seconds to pause after a failed login so accounts do not get locked), `allow_insecure_fallback`, `captcha_command`, `field_map`, `extra_fields`, `login_url`, `login_method`, `logout_url`, `max_steps`.

## Limitations

- Portals that need a real browser (heavy JavaScript, device fingerprinting, SMS/OTP, SSO redirects to a third party) cannot be automated.
- Captcha solving is up to you (see above).
- The binaries are not code-signed.

## Development

```sh
python -m unittest discover -s tests -v    # fake portals incl. self-signed TLS, CSRF, captchas
sh packaging/build_deb.sh                  # needs dpkg-deb
sh packaging/build_dmg.sh                  # needs pyinstaller, on macOS
git tag v0.1.0 && git push --tags          # CI builds .deb/.dmg/.exe and publishes the release
```

MIT licensed.
