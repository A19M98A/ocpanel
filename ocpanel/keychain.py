"""Remember the VPN password somewhere better than config.json.

Never in config.json: that file is plain text, and it is copied around and read
by anything that can read your home directory.

Three places, best first:
  * macOS   - the login keychain, encrypted and locked with your login.
  * Linux   - the desktop keyring through `secret-tool` (libsecret), when it is
              installed; same idea, unlocked with your login.
  * neither - a file in your own config directory, mode 0600. Not encrypted.
              The panel says so when it falls back to this, so you can decide.

The panel usually runs as root under sudo, but a keyring belongs to you, so
every command is run back as the invoking user - and on Linux that also means
pointing it at your session bus, which root cannot see.
"""
from __future__ import annotations

import json
import os
import pwd
import subprocess

from . import plat

SERVICE = "ocpanel-vpn"
SUBSCRIPTION_ACCOUNT = "subscription"        # the original single-subscription slot
LABEL = "VPN password saved by ocpanel"
TIMEOUT = 15.0


def source_account(source_id: str) -> str:
    return f"source-{source_id}"


def account_for(server: str, user: str) -> str:
    """One entry per account, so several profiles can be remembered."""
    return f"{user}@{server}" if user else server


def store_name() -> str:
    """What to call the store in the interface."""
    return {"keychain": "login keychain",
            "secret-tool": "desktop keyring"}.get(plat.secret_store(), "config file")


def encrypted() -> bool:
    """False only for the plain-file fallback, which the panel must own up to."""
    return plat.secret_store() != "file"


def _invoking_user() -> str | None:
    """Whose keyring to use: the human who ran sudo, not root."""
    if os.geteuid() != 0:
        return None                       # already running as them
    name = os.environ.get("SUDO_USER")
    if name:
        return name
    try:
        return pwd.getpwuid(os.stat(os.environ.get("HOME", "/")).st_uid).pw_name
    except (OSError, KeyError):
        return None


def _as_user(cmd: list[str]) -> list[str]:
    """Run a command back as the invoking user, with their session bus.

    On Linux the keyring is reached over the user's D-Bus session, which lives
    at /run/user/<uid>/bus and is invisible to root, so pass it explicitly.
    """
    user = _invoking_user()
    if not user:
        return cmd
    if plat.MACOS:
        return ["sudo", "-u", user, *cmd]
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError:
        return ["sudo", "-u", user, *cmd]
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"unix:path=/run/user/{uid}/bus"
    # Via `env`, not `sudo VAR=value`: sudoers may refuse to let sudo set them.
    return ["sudo", "-u", user, "env", f"DBUS_SESSION_BUS_ADDRESS={bus}",
            f"XDG_RUNTIME_DIR=/run/user/{uid}", *cmd]


def _run(cmd: list[str], stdin: str | None = None) -> tuple[int, str]:
    try:
        p = subprocess.run(_as_user(cmd), capture_output=True, text=True,
                           input=stdin, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return -1, f"the {store_name()} did not answer (it may be asking for permission)"
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)
    return p.returncode, (p.stdout + p.stderr).strip()


# ------------------------------------------------------------------- macOS

def _security(args: list[str]) -> tuple[int, str]:
    return _run(["security", *args])


# ------------------------------------------------------------------- Linux

def _secret_tool(args: list[str], stdin: str | None = None) -> tuple[int, str]:
    return _run(["secret-tool", *args], stdin=stdin)


# -------------------------------------------------------------- plain file

def _secrets_path():
    from .config import CONFIG_DIR       # late: config -> rules -> netinfo
    return CONFIG_DIR / "secrets.json"


def _secrets_read() -> dict[str, str]:
    try:
        data = json.loads(_secrets_path().read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}


def _secrets_write(data: dict[str, str]) -> tuple[bool, str]:
    from .config import _own
    path = _secrets_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Create it 0600 before anything goes in, never 0644-then-chmod.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(data, handle, indent=2)
        os.chmod(path, 0o600)
        _own(path)
    except OSError as exc:
        return False, str(exc)
    return True, ""


# ------------------------------------------------------------------- common

def save(account: str, password: str) -> tuple[bool, str]:
    store = plat.secret_store()
    if store == "keychain":
        # -U replaces an existing entry; -T lets `security` read it back without a prompt.
        rc, out = _security(["add-generic-password", "-U", "-a", account, "-s", SERVICE,
                             "-w", password, "-T", "/usr/bin/security", "-j", LABEL])
        if rc == 0:
            return True, "saved to your login keychain"
        return False, out or f"security exited with status {rc}"
    if store == "secret-tool":
        # The password goes in on stdin, so it never appears in the process list.
        rc, out = _secret_tool(["store", "--label", LABEL,
                                "service", SERVICE, "account", account],
                               stdin=password)
        if rc == 0:
            return True, "saved to your desktop keyring"
        hint = plat.install_hint("libsecret-tools")
        return False, out or f"secret-tool exited with status {rc} - {hint}"
    data = _secrets_read()
    data[account] = password
    ok, err = _secrets_write(data)
    if ok:
        return True, (f"saved to {_secrets_path()} - that file is private to you "
                      f"but not encrypted; install libsecret-tools for a keyring")
    return False, err


def load(account: str) -> str | None:
    store = plat.secret_store()
    if store == "keychain":
        rc, out = _security(["find-generic-password", "-w", "-a", account, "-s", SERVICE])
        return out if rc == 0 and out else None
    if store == "secret-tool":
        rc, out = _secret_tool(["lookup", "service", SERVICE, "account", account])
        return out if rc == 0 and out else None
    return _secrets_read().get(account) or None


def forget(account: str) -> tuple[bool, str]:
    store = plat.secret_store()
    if store == "keychain":
        rc, out = _security(["delete-generic-password", "-a", account, "-s", SERVICE])
        if rc == 0:
            return True, "removed from your login keychain"
        if rc == 44:                      # errSecItemNotFound
            return False, "nothing was saved"
        return False, out or f"security exited with status {rc}"
    if store == "secret-tool":
        if not has(account):              # `clear` succeeds even with nothing to clear
            return False, "nothing was saved"
        rc, out = _secret_tool(["clear", "service", SERVICE, "account", account])
        if rc == 0:
            return True, "removed from your desktop keyring"
        return False, out or f"secret-tool exited with status {rc}"
    data = _secrets_read()
    if account not in data:
        return False, "nothing was saved"
    del data[account]
    ok, err = _secrets_write(data)
    return (True, "removed from your config file") if ok else (False, err)


def has(account: str) -> bool:
    store = plat.secret_store()
    if store == "keychain":
        return _security(["find-generic-password", "-a", account, "-s", SERVICE])[0] == 0
    if store == "secret-tool":
        rc, out = _secret_tool(["lookup", "service", SERVICE, "account", account])
        return rc == 0 and bool(out)
    return account in _secrets_read()
