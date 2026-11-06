"""Panel configuration - profile plus the bypass list - stored as JSON."""
from __future__ import annotations

import json
import os
import pwd
from dataclasses import dataclass, field
from pathlib import Path

from .rules import Rule


def invoking_home() -> Path:
    """Home of the human running the panel, not root's.

    The panel needs root to touch the routing table, so it is normally started
    with sudo - but the config belongs to the user, and Path.home() under sudo
    would point at /var/root.
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and os.geteuid() == 0:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


CONFIG_DIR = Path(os.environ.get("OCPANEL_HOME", invoking_home() / ".config" / "ocpanel"))
CONFIG_FILE = CONFIG_DIR / "config.json"
STATE_FILE = CONFIG_DIR / "state.json"

# Which way round the tunnel works.
MODE_VPN = "vpn"         # everything through the VPN, except the bypass list
MODE_DIRECT = "direct"   # everything direct, except the VPN list
MODES = (MODE_VPN, MODE_DIRECT)

DEFAULT_THEME = "tokyo-night"


def _own(path: Path) -> None:
    """Keep files readable by the invoking user even when written under sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid and gid:
        try:
            os.chown(path, int(uid), int(gid))
        except OSError:
            pass


def load_state() -> dict:
    """Bookkeeping the panel needs to undo its own routes later."""
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2) + "\n")
    _own(STATE_FILE)


@dataclass
class Profile:
    server: str = ""
    user: str = ""
    extra_args: list[str] = field(default_factory=list)
    # Optional shell command whose stdout is the VPN password, piped straight to
    # openconnect --passwd-on-stdin. Use your own secret store, e.g.
    #   security find-generic-password -w -s ocpanel-vpn
    # Leave empty and openconnect will prompt you on the terminal instead.
    auth_command: str = ""
    # True once you have ticked "remember" - the password itself lives in the
    # macOS login keychain, never here. See keychain.py.
    save_password: bool = False
    # "openconnect" or "subscription" (a VLESS/VMess/Trojan link run by sing-box).
    kind: str = "openconnect"
    server_name: str = ""          # the chosen entry from the subscription


@dataclass
class Source:
    """Where servers come from: a subscription URL, or one pasted link.

    Only the name and kind live here - the URL itself is a credential and stays
    in the login keychain under "source-<id>".
    """
    id: str
    name: str
    kind: str = "subscription"          # subscription | link

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "kind": self.kind}

    @classmethod
    def from_dict(cls, d: dict) -> "Source":
        return cls(id=str(d.get("id", "")), name=str(d.get("name", "")),
                   kind=str(d.get("kind", "subscription")))


@dataclass
class Config:
    profile: Profile = field(default_factory=Profile)
    mode: str = MODE_VPN
    disconnect_on_quit: bool = True                       # q takes the VPN down too
    theme: str = DEFAULT_THEME                            # any Textual theme name
    sources: list[Source] = field(default_factory=list)   # subscriptions and links
    rules: list[Rule] = field(default_factory=list)       # bypass list (vpn mode)
    vpn_rules: list[Rule] = field(default_factory=list)   # VPN list (direct mode)

    @property
    def active_rules(self) -> list[Rule]:
        """The list the current mode acts on. The other one is kept, untouched."""
        return self.vpn_rules if self.mode == MODE_DIRECT else self.rules

    @classmethod
    def load(cls) -> "Config":
        if not CONFIG_FILE.exists():
            return cls()
        try:
            raw = json.loads(CONFIG_FILE.read_text())
        except (OSError, json.JSONDecodeError):
            return cls()
        prof = raw.get("profile", {})
        mode = raw.get("mode", MODE_VPN)
        return cls(
            mode=mode if mode in MODES else MODE_VPN,
            disconnect_on_quit=bool(raw.get("disconnect_on_quit", True)),
            theme=str(raw.get("theme", DEFAULT_THEME)),
            profile=Profile(
                server=str(prof.get("server", "")),
                user=str(prof.get("user", "")),
                extra_args=list(prof.get("extra_args", [])),
                auth_command=str(prof.get("auth_command", "")),
                save_password=bool(prof.get("save_password", False)),
                kind=str(prof.get("kind", "openconnect")),
                server_name=str(prof.get("server_name", "")),
            ),
            sources=[Source.from_dict(x) for x in raw.get("sources", []) if x.get("id")],
            rules=[Rule.from_dict(r) for r in raw.get("rules", []) if r.get("target")],
            vpn_rules=[Rule.from_dict(r) for r in raw.get("vpn_rules", []) if r.get("target")],
        )

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "profile": {
                "server": self.profile.server,
                "user": self.profile.user,
                "extra_args": self.profile.extra_args,
                "auth_command": self.profile.auth_command,
                "save_password": self.profile.save_password,
                "kind": self.profile.kind,
                "server_name": self.profile.server_name,
            },
            "mode": self.mode,
            "disconnect_on_quit": self.disconnect_on_quit,
            "theme": self.theme,
            "sources": [x.to_dict() for x in self.sources],
            "rules": [r.to_dict() for r in self.rules],
            "vpn_rules": [r.to_dict() for r in self.vpn_rules],
        }
        tmp = CONFIG_FILE.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2) + "\n")
        tmp.replace(CONFIG_FILE)
        _own(CONFIG_FILE)
        _own(CONFIG_DIR)
