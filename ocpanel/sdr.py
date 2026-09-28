"""Valve Steam Datagram Relay directory.

Dota 2 (and CS, TF2 ...) do not talk to one fixed server. The client connects to
whichever SDR relay cluster is closest, so a bypass rule has to cover the relay
IPs. Valve publishes the current list; we cache it so the panel works offline.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass, field

from .config import CONFIG_DIR

SDR_URL = "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid={appid}"
DOTA2_APPID = 570
CACHE = CONFIG_DIR / "sdr.json"
MAX_AGE = 7 * 24 * 3600


@dataclass
class Pop:
    code: str
    desc: str
    networks: list[ipaddress.IPv4Network] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.code} - {self.desc}"


def fetch(appid: int = DOTA2_APPID, timeout: float = 20.0) -> dict:
    """Download the relay directory, falling back to the cache on failure.

    Uses curl rather than urllib on purpose: a python.org Python ships without
    root certificates until you run Install Certificates.command, so urllib
    fails TLS verification on a stock install. curl uses the system trust store
    and is always present on macOS.
    """
    try:
        p = subprocess.run(
            ["curl", "-fsS", "--max-time", str(int(timeout)), SDR_URL.format(appid=appid)],
            capture_output=True, text=True, timeout=timeout + 5)
        if p.returncode == 0:
            data = json.loads(p.stdout)
            if data.get("pops"):
                CONFIG_DIR.mkdir(parents=True, exist_ok=True)
                CACHE.write_text(json.dumps(data))
                return data
    except (subprocess.SubprocessError, OSError, json.JSONDecodeError):
        pass                               # offline or blocked - fall back to cache
    return load_cache()


def load_cache() -> dict:
    try:
        return json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def cache_age() -> float | None:
    try:
        return time.time() - CACHE.stat().st_mtime
    except OSError:
        return None


def pops(data: dict | None = None) -> list[Pop]:
    """Relay clusters, each reduced to the /24s its relays live in.

    Valve moves individual relay IPs around inside a cluster, so covering the
    whole /24 is what keeps a bypass rule working next week.
    """
    data = data if data is not None else load_cache()
    out: list[Pop] = []
    for code, p in sorted((data.get("pops") or {}).items()):
        nets = sorted({
            ipaddress.ip_network(f"{r['ipv4']}/24", strict=False)
            for r in p.get("relays", []) or [] if r.get("ipv4")
        })
        if nets:
            out.append(Pop(code=code, desc=p.get("desc", ""), networks=nets))
    return out


def lookup(ip: str, data: dict | None = None) -> Pop | None:
    """Which relay cluster an address belongs to, if any."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for pop in pops(data):
        if any(addr in net for net in pop.networks):
            return pop
    return None
