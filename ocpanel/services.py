"""Published IP ranges for services too big to route by hostname.

A hostname rule turns into the one or two addresses DNS returns at that moment.
That is fine for a small site, and useless for something like YouTube: the page,
the API, thumbnails and the video streams all live on different hostnames spread
over hundreds of Google addresses, and DNS hands out different ones each time.
Routing the ranges the operator publishes covers all of it.
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from .config import CONFIG_DIR

CACHE_DIR = CONFIG_DIR / "services"


def _curl_json(url: str, timeout: int = 20) -> dict:
    # curl, not urllib: a python.org Python has no root certificates by default.
    p = subprocess.run(["curl", "-fsS", "--max-time", str(timeout), url],
                       capture_output=True, text=True, timeout=timeout + 5)
    if p.returncode != 0:
        raise OSError(p.stderr.strip() or f"curl exit {p.returncode}")
    return json.loads(p.stdout)


def _v4(doc: dict) -> list[ipaddress.IPv4Network]:
    return [ipaddress.ip_network(p["ipv4Prefix"]) for p in doc.get("prefixes", [])
            if "ipv4Prefix" in p]


def _google() -> list[ipaddress.IPv4Network]:
    """Google's own services: goog.json minus the Google Cloud customer ranges.

    goog.json alone also contains every website hosted on Google Cloud, which
    would drag unrelated sites into the list. Google documents subtracting
    cloud.json to get just its own services - YouTube included.
    """
    everything = _v4(_curl_json("https://www.gstatic.com/ipranges/goog.json"))
    customers = _v4(_curl_json("https://www.gstatic.com/ipranges/cloud.json"))
    kept: list[ipaddress.IPv4Network] = []
    for net in everything:
        parts = [net]
        for cust in (c for c in customers if c.overlaps(net)):
            remaining = []
            for part in parts:
                if not cust.overlaps(part):
                    remaining.append(part)
                elif not part.subnet_of(cust):            # wholly customer: drop it
                    remaining.extend(part.address_exclude(cust))
            parts = remaining
        kept.extend(parts)
    return list(ipaddress.collapse_addresses(kept))


@dataclass
class Service:
    name: str
    source: str
    fetch: Callable[[], list[ipaddress.IPv4Network]]


SERVICES: dict[str, Service] = {
    "google": Service("Google & YouTube", "gstatic.com/ipranges (goog.json - cloud.json)",
                      _google),
}


def _cache(key: str):
    return CACHE_DIR / f"{key}.json"


def cached(key: str) -> list[str]:
    try:
        return list(json.loads(_cache(key).read_text())["ranges"])
    except (OSError, json.JSONDecodeError, KeyError):
        return []


def cache_age(key: str) -> float | None:
    try:
        return time.time() - _cache(key).stat().st_mtime
    except OSError:
        return None


MAX_AGE = 7 * 24 * 3600


def fetch(key: str) -> list[str]:
    """Download fresh ranges, falling back to the cached copy if that fails."""
    svc = SERVICES[key]
    try:
        ranges = [str(n) for n in svc.fetch()]
    except (OSError, ValueError, subprocess.SubprocessError):
        return cached(key)
    if ranges:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _cache(key).write_text(json.dumps({"service": key, "source": svc.source,
                                           "ranges": ranges}) + "\n")
    return ranges or cached(key)


def owner(ip: str) -> str | None:
    """Which known service an address belongs to, from the cached ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for key in SERVICES:
        if any(addr in ipaddress.ip_network(r) for r in cached(key)):
            return key
    return None
