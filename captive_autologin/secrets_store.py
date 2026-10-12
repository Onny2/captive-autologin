"""Password storage: macOS Keychain, Windows Credential Manager, secret-tool (or a 0600 file) on Linux."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess

from .config import APP, SYSTEM, app_dir

log = logging.getLogger("captive-autologin")
LABEL = "Captive portal autologin"


def fallback_file():
    return app_dir() / ".password"


if SYSTEM == "Windows":
    import ctypes
    from ctypes import wintypes

    class _CREDENTIAL(ctypes.Structure):
        _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                    ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                    ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                    ("CredentialBlob", ctypes.POINTER(ctypes.c_char)), ("Persist", wintypes.DWORD),
                    ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p),
                    ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

    _advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    _CRED_TYPE_GENERIC, _CRED_PERSIST_LOCAL_MACHINE = 1, 2

    def _win_write(target, user, password):
        blob = password.encode("utf-16-le")
        buf = ctypes.create_string_buffer(blob, len(blob))
        cred = _CREDENTIAL(Type=_CRED_TYPE_GENERIC, TargetName=target, UserName=user,
                           CredentialBlobSize=len(blob), Persist=_CRED_PERSIST_LOCAL_MACHINE,
                           CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        if not _advapi.CredWriteW(ctypes.byref(cred), 0):
            raise ctypes.WinError(ctypes.get_last_error())

    def _win_read(target):
        p = ctypes.POINTER(_CREDENTIAL)()
        if not _advapi.CredReadW(target, _CRED_TYPE_GENERIC, 0, ctypes.byref(p)):
            return None
        try:
            c = p.contents
            return ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le")
        finally:
            _advapi.CredFree(p)

    def _win_delete(target):
        _advapi.CredDeleteW(target, _CRED_TYPE_GENERIC, 0)


def save(user, password):
    """Returns where the password ended up: "keyring" or "file"."""
    delete()
    if SYSTEM == "Darwin":
        subprocess.run(["/usr/bin/security", "add-generic-password", "-U", "-s", APP, "-a", user,
                        "-l", LABEL, "-w", password], check=True)
        return "keyring"
    if SYSTEM == "Windows":
        _win_write(APP, user, password)
        return "keyring"
    if shutil.which("secret-tool"):
        r = subprocess.run(["secret-tool", "store", "--label=" + LABEL, "service", APP, "account", user],
                           input=password.encode(), capture_output=True)
        if r.returncode == 0 and load() == password:
            return "keyring"
    path = fallback_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(password)
    return "file"


def load():
    try:
        if SYSTEM == "Darwin":
            r = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", APP, "-w"],
                               capture_output=True, text=True)
            return r.stdout.rstrip("\n") if r.returncode == 0 else None
        if SYSTEM == "Windows":
            return _win_read(APP)
        if shutil.which("secret-tool"):
            r = subprocess.run(["secret-tool", "lookup", "service", APP], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout:
                return r.stdout.rstrip("\n")
        if fallback_file().exists():
            return fallback_file().read_text().rstrip("\n")
    except Exception as e:
        log.error("Could not read the stored password: %s", e)
    return None


def stored_user():
    """macOS only: account already stored in the Keychain (for `install --reuse`)."""
    if SYSTEM != "Darwin":
        return None
    r = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", APP],
                       capture_output=True, text=True)
    m = re.search(r'"acct"<blob>="(.*)"', r.stdout)
    return m.group(1) if m else None


def delete():
    if SYSTEM == "Darwin":
        while subprocess.run(["/usr/bin/security", "delete-generic-password", "-s", APP],
                             capture_output=True).returncode == 0:
            pass
    elif SYSTEM == "Windows":
        _win_delete(APP)
    else:
        if shutil.which("secret-tool"):
            subprocess.run(["secret-tool", "clear", "service", APP], capture_output=True)
        fallback_file().unlink(missing_ok=True)
