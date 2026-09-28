"""Bypass rules: targets whose traffic must skip the VPN and go out the real link."""
from __future__ import annotations

import ipaddress
import os
import subprocess
from dataclasses import dataclass, field

from . import netinfo

SERVICE_PREFIX = "service:"


@dataclass
class Rule:
    target: str                 # 1.2.3.4 | 1.2.3.0/24 | game.example.com | service:google
    note: str = ""
    enabled: bool = True
    addresses: list[str] = field(default_factory=list)   # resolved, runtime only
    error: str = ""

    @property
    def kind(self) -> str:
        if self.target.startswith(SERVICE_PREFIX):
            return "service"
        try:
            ipaddress.ip_network(self.target, strict=False)
        except ValueError:
            return "host"
        return "subnet" if "/" in self.target else "address"

    def to_dict(self) -> dict:
        return {"target": self.target, "note": self.note, "enabled": self.enabled}

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(target=str(d.get("target", "")), note=str(d.get("note", "")),
                   enabled=bool(d.get("enabled", True)))

    def networks(self) -> list[ipaddress.IPv4Network]:
        """The concrete IPv4 networks this rule currently covers."""
        self.error = ""
        if self.kind == "service":
            from . import services          # late: services -> config -> rules
            key = self.target[len(SERVICE_PREFIX):]
            if key not in services.SERVICES:
                self.error = f"unknown service '{key}'"
                return []
            ranges = services.cached(key)
            self.addresses = ranges
            if not ranges:
                self.error = "ranges not downloaded - press s"
            return [ipaddress.ip_network(r) for r in ranges]
        if self.kind == "host":
            ips = netinfo.resolve(self.target)
            self.addresses = ips
            if not ips:
                self.error = "does not resolve"
            return [ipaddress.ip_network(f"{ip}/32") for ip in ips]
        try:
            net = ipaddress.ip_network(self.target, strict=False)
        except ValueError as exc:
            self.error = str(exc)
            return []
        if net.version != 4:
            self.error = "IPv6 not supported"
            return []
        self.addresses = [str(net)]
        return [net]


def is_root() -> bool:
    return os.geteuid() == 0


def _route(args: list[str]) -> tuple[bool, str]:
    try:
        p = subprocess.run(["route", "-n", *args], capture_output=True, text=True, timeout=10)
    except (subprocess.SubprocessError, OSError) as exc:
        return False, str(exc)
    out = (p.stdout + p.stderr).strip()
    return p.returncode == 0, out


def _spec(net: ipaddress.IPv4Network) -> list[str]:
    if net.prefixlen == 32:
        return ["-host", str(net.network_address)]
    return ["-net", str(net.network_address), "-netmask", str(net.netmask)]


def add_route(net: ipaddress.IPv4Network, gateway: str) -> tuple[bool, str]:
    """Point one network at the physical gateway so it bypasses the tunnel.

    More specific than the VPN's default route, so the kernel prefers it.
    """
    ok, out = _route(["add", *_spec(net), gateway])
    if not ok and "File exists" in out:
        return _route(["change", *_spec(net), gateway])
    return ok, out


def add_tunnel_route(net: ipaddress.IPv4Network, iface: str) -> tuple[bool, str]:
    """Send one network into the VPN tunnel, whatever the default route says."""
    ok, out = _route(["add", *_spec(net), "-interface", iface])
    if not ok and "File exists" in out:
        return _route(["change", *_spec(net), "-interface", iface])
    return ok, out


def delete_route(net: ipaddress.IPv4Network) -> tuple[bool, str]:
    return _route(["delete", *_spec(net)])


def was_absent(out: str) -> bool:
    """A delete that failed only because the route was never there."""
    return "not in table" in out


def verify(net: ipaddress.IPv4Network) -> str:
    """Which interface traffic to this network actually leaves by, right now."""
    return netinfo.route_iface(str(net.network_address))
