"""Remember the VPN password in the macOS login keychain.

Never in config.json: that file is plain text, and it is copied around and read
by anything that can read your home directory. The keychain is encrypted, locked
with your login, and the entry here is readable only by /usr/bin/security.

The panel usually runs as root under sudo, but the keychain belongs to you, so
every command is run back as the invoking user.
"""
from __future__ import annotations

import os
import pwd
import subprocess

SERVICE = "ocpanel-vpn"
SUBSCRIPTION_ACCOUNT = "subscription"        # the original single-subscription slot


def source_account(source_id: str) -> str:
    return f"source-{source_id}"
TIMEOUT = 15.0


def account_for(server: str, user: str) -> str:
    """One entry per account, so several profiles can be remembered."""
    return f"{user}@{server}" if user else server


def _invoking_user() -> str | None:
    """Whose keychain to use: the human who ran sudo, not root."""
    if os.geteuid() != 0:
        return None                       # already running as them
    name = os.environ.get("SUDO_USER")
    if name:
        return name
    try:
        return pwd.getpwuid(os.stat(os.environ.get("HOME", "/")).st_uid).pw_name
    except (OSError, KeyError):
        return None


def _security(args: list[str]) -> tuple[int, str]:
    cmd = ["security", *args]
    user = _invoking_user()
    if user:
        cmd = ["sudo", "-u", user, *cmd]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return -1, "the keychain did not answer (it may be asking for permission)"
    except (OSError, subprocess.SubprocessError) as exc:
        return -1, str(exc)
    return p.returncode, (p.stdout + p.stderr).strip()


def save(account: str, password: str) -> tuple[bool, str]:
    # -U replaces an existing entry; -T lets `security` read it back without a prompt.
    rc, out = _security(["add-generic-password", "-U", "-a", account, "-s", SERVICE,
                         "-w", password, "-T", "/usr/bin/security",
                         "-j", "VPN password saved by ocpanel"])
    if rc == 0:
        return True, "saved to your login keychain"
    return False, out or f"security exited with status {rc}"


def load(account: str) -> str | None:
    rc, out = _security(["find-generic-password", "-w", "-a", account, "-s", SERVICE])
    return out if rc == 0 and out else None


def forget(account: str) -> tuple[bool, str]:
    rc, out = _security(["delete-generic-password", "-a", account, "-s", SERVICE])
    if rc == 0:
        return True, "removed from your login keychain"
    if rc == 44:                          # errSecItemNotFound
        return False, "nothing was saved"
    return False, out or f"security exited with status {rc}"


def has(account: str) -> bool:
    return _security(["find-generic-password", "-a", account, "-s", SERVICE])[0] == 0
