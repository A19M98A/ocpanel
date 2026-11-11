"""Which operating system we are on, and the bits that differ because of it.

ocpanel works the same way on both systems - it edits the routing table and
watches what the kernel really does - but macOS and Linux disagree about every
command used to do that. The parsers live here, taking text rather than running
anything, so both platforms' output can be tested from either one.
"""
from __future__ import annotations

import ipaddress
import re
import sys

MACOS = sys.platform == "darwin"
LINUX = sys.platform.startswith("linux")
NAME = "macOS" if MACOS else "Linux" if LINUX else sys.platform

# Interfaces a tunnel shows up as. utun/ppp/ipsec are macOS; tun/tap/wg and the
# vendor names below are Linux.
TUNNEL_PREFIXES = ("utun", "ppp", "ipsec", "tun", "tap", "wg", "nordlynx",
                   "proton", "gpd", "wgpia")


def is_tunnel(iface: str) -> bool:
    return bool(iface) and iface.startswith(TUNNEL_PREFIXES)


# ----------------------------------------------------------- routing table

def _which(macos: bool | None) -> bool:
    return MACOS if macos is None else macos


def routes_command(macos: bool | None = None) -> list[str]:
    return (["netstat", "-rn", "-f", "inet"] if _which(macos)
            else ["ip", "-4", "route", "show"])


def _expand_bsd_dest(dest: str) -> ipaddress.IPv4Network | None:
    """netstat abbreviates destinations: '128.0/1' means 128.0.0.0/1."""
    if dest == "default":
        return ipaddress.ip_network("0.0.0.0/0")
    addr, sep, plen = dest.partition("/")
    parts = addr.split(".")
    if not sep or not 1 <= len(parts) <= 4:
        return None
    try:
        return ipaddress.ip_network(f"{'.'.join(parts + ['0'] * (4 - len(parts)))}/{plen}")
    except ValueError:
        return None


def _expand_linux_dest(dest: str) -> ipaddress.IPv4Network | None:
    if dest == "default":
        return ipaddress.ip_network("0.0.0.0/0")
    try:
        return ipaddress.ip_network(dest, strict=False)
    except ValueError:
        return None


def expand_dest(dest: str, macos: bool | None = None) -> ipaddress.IPv4Network | None:
    return _expand_bsd_dest(dest) if _which(macos) else _expand_linux_dest(dest)


def parse_routes(text: str, macos: bool | None = None) -> list[tuple[str, str, str]]:
    """Every route as (destination, gateway, interface).

    Destination is left exactly as the system wrote it; expand_dest turns it
    into a network when that matters.
    """
    macos = MACOS if macos is None else macos
    out: list[tuple[str, str, str]] = []
    if macos:
        for line in text.splitlines():
            f = line.split()
            if len(f) < 4 or f[0] in ("Routing", "Internet:", "Destination"):
                continue
            iface = f[-1]
            if iface.isdigit() or "." in iface:        # Expire column present
                iface = f[-2]
            out.append((f[0], f[1], iface))
        return out
    # Linux: "default via 192.168.1.1 dev eth0 ..." / "10.0.0.0/8 dev tun0 ..."
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        # A route whose link is down cannot carry anything, and offering one as a
        # bypass gateway would silently black-hole the traffic. Machines with a
        # spare bridge or USB interface have these sitting in the table.
        if "linkdown" in f:
            continue
        dest = f[0]
        gateway = f[f.index("via") + 1] if "via" in f else ""
        iface = f[f.index("dev") + 1] if "dev" in f else ""
        if dest and iface:
            out.append((dest, gateway, iface))
    return out


def route_get_command(target: str, macos: bool | None = None) -> list[str]:
    return (["route", "-n", "get", target] if _which(macos)
            else ["ip", "-4", "route", "get", target])


def parse_route_get(text: str, macos: bool | None = None) -> dict[str, str]:
    """What the kernel would do with one address: interface, gateway, source."""
    macos = MACOS if macos is None else macos
    info: dict[str, str] = {}
    if macos:
        for line in text.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() in ("destination", "mask", "gateway", "interface"):
                info[key.strip()] = value.strip()
        return info
    # Linux: "1.1.1.1 via 192.168.1.1 dev eth0 src 192.168.1.5 uid 1000"
    f = text.split()
    for key, word in (("gateway", "via"), ("interface", "dev"), ("source", "src")):
        if word in f:
            info[key] = f[f.index(word) + 1]
    if f:
        info.setdefault("destination", f[0])
    return info


# ------------------------------------------------------------- interfaces

def addresses_command(macos: bool | None = None) -> list[str]:
    return ["ifconfig"] if _which(macos) else ["ip", "-4", "-o", "addr", "show"]


def parse_addresses(text: str, macos: bool | None = None) -> dict[str, str]:
    """interface -> its first IPv4 address."""
    macos = MACOS if macos is None else macos
    found: dict[str, str] = {}
    if macos:
        iface = ""
        for line in text.splitlines():
            if line and not line[0].isspace():
                iface = line.split(":", 1)[0]
            elif iface and line.strip().startswith("inet "):
                found.setdefault(iface, line.split()[1])
        return found
    # Linux: "2: eth0    inet 192.168.1.5/24 brd ... scope global eth0"
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 4 and f[2] == "inet":
            found.setdefault(f[1], f[3].split("/")[0])
    return found


def counters_command(iface: str) -> list[str]:
    """Only macOS needs a command; Linux reads sysfs instead."""
    return ["netstat", "-I", iface, "-b", "-n"]


def parse_counters(text: str, iface: str) -> tuple[int, int]:
    """(rx, tx) from `netstat -I`. Point-to-point links have no hardware
    address, so the columns shift - index from the end of the <Link#..> row."""
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[0] == iface and f[2].startswith("<Link"):
            try:
                return int(f[-5]), int(f[-2])
            except (ValueError, IndexError):
                continue
    return 0, 0


# -------------------------------------------------------------------- dns

def dns_command(macos: bool | None = None) -> list[str]:
    return ["scutil", "--dns"] if _which(macos) else ["resolvectl", "status"]


def parse_dns(text: str, macos: bool | None = None) -> list[str]:
    macos = MACOS if macos is None else macos
    if macos:
        return sorted({m for m in re.findall(r"nameserver\[\d+\] : (\S+)", text)})
    # resolvectl: "DNS Servers: 192.168.1.1 1.1.1.1" possibly wrapped
    found: set[str] = set()
    collecting = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("DNS Servers:"):
            collecting = True
            stripped = stripped.split(":", 1)[1]
        elif collecting and not line.startswith((" ", "\t")):
            collecting = False
        elif not collecting:
            continue
        found.update(re.findall(r"[0-9a-fA-F:.]{3,}", stripped))
    return sorted(f for f in found if f)


def parse_resolv_conf(text: str) -> list[str]:
    """Fallback for systems without systemd-resolved."""
    return sorted({m for m in re.findall(r"^\s*nameserver\s+(\S+)", text, re.M)})


# ----------------------------------------------------------------- routes

def add_route_command(net: ipaddress.IPv4Network, gateway: str, macos: bool | None = None) -> list[str]:
    if _which(macos):
        if net.prefixlen == 32:
            return ["route", "-n", "add", "-host", str(net.network_address), gateway]
        return ["route", "-n", "add", "-net", str(net.network_address),
                "-netmask", str(net.netmask), gateway]
    return ["ip", "route", "replace", str(net), "via", gateway]


def add_tunnel_route_command(net: ipaddress.IPv4Network, iface: str, macos: bool | None = None) -> list[str]:
    if _which(macos):
        if net.prefixlen == 32:
            return ["route", "-n", "add", "-host", str(net.network_address),
                    "-interface", iface]
        return ["route", "-n", "add", "-net", str(net.network_address),
                "-netmask", str(net.netmask), "-interface", iface]
    return ["ip", "route", "replace", str(net), "dev", iface]


def change_route_command(net: ipaddress.IPv4Network, gateway: str, macos: bool | None = None) -> list[str]:
    """macOS needs `change` when a route already exists; `ip route replace` does
    both, so on Linux this is the same command."""
    if _which(macos):
        if net.prefixlen == 32:
            return ["route", "-n", "change", "-host", str(net.network_address), gateway]
        return ["route", "-n", "change", "-net", str(net.network_address),
                "-netmask", str(net.netmask), gateway]
    return add_route_command(net, gateway, macos)


def change_tunnel_route_command(net: ipaddress.IPv4Network, iface: str, macos: bool | None = None) -> list[str]:
    if _which(macos):
        if net.prefixlen == 32:
            return ["route", "-n", "change", "-host", str(net.network_address),
                    "-interface", iface]
        return ["route", "-n", "change", "-net", str(net.network_address),
                "-netmask", str(net.netmask), "-interface", iface]
    return add_tunnel_route_command(net, iface, macos)


def delete_route_command(net: ipaddress.IPv4Network, macos: bool | None = None) -> list[str]:
    if _which(macos):
        if net.prefixlen == 32:
            return ["route", "-n", "delete", "-host", str(net.network_address)]
        return ["route", "-n", "delete", "-net", str(net.network_address),
                "-netmask", str(net.netmask)]
    return ["ip", "route", "del", str(net)]


EXISTS = ("file exists", "rtnetlink answers: file exists")
ABSENT = ("not in table", "no such process", "rtnetlink answers: no such process")


def route_exists(output: str) -> bool:
    return any(m in output.lower() for m in EXISTS)


def route_absent(output: str) -> bool:
    return any(m in output.lower() for m in ABSENT)


# ------------------------------------------------------------- secret store

def secret_store() -> str:
    """Where a password can be kept: the macOS keychain, libsecret, or a file."""
    if MACOS:
        return "keychain"
    import shutil
    return "secret-tool" if shutil.which("secret-tool") else "file"


# ------------------------------------------------------------------ extras

def sockets_tool() -> str:
    """Live connections. lsof exists on both; ss is the Linux fallback."""
    import shutil
    return "lsof" if MACOS or shutil.which("lsof") else "ss"


def sockets_command(tool: str | None = None) -> list[str]:
    tool = sockets_tool() if tool is None else tool
    return ["lsof", "-i", "-n", "-P"] if tool == "lsof" else ["ss", "-tunp"]


_SS_PROCESS = re.compile(r'\(\("([^"]+)",pid=(\d+)')


def parse_sockets(text: str, tool: str) -> list[tuple[str, int, str, str, str]]:
    """Connections as (command, pid, proto, local, remote).

    proto is upper-case TCP/UDP either way; local and remote keep the
    host:port spelling the tool used.
    """
    rows: list[tuple[str, int, str, str, str]] = []
    if tool == "lsof":
        for line in text.splitlines()[1:]:
            f = line.split()
            if len(f) < 9:
                continue
            proto, name = f[7], f[8]
            if proto not in ("TCP", "UDP") or "->" not in name:
                continue
            local, _, remote = name.partition("->")
            try:
                rows.append((f[0], int(f[1]), proto, local, remote))
            except ValueError:
                continue
        return rows
    # ss: "tcp ESTAB 0 0 192.168.1.5:54321 1.2.3.4:443 users:(("dota2",pid=12,fd=5))"
    for line in text.splitlines():
        f = line.split()
        if len(f) < 7 or f[0].lower() not in ("tcp", "udp"):
            continue
        found = _SS_PROCESS.search(line)
        if not found:
            continue                       # no permission to see the process
        try:
            rows.append((found.group(1), int(found.group(2)),
                         f[0].upper(), f[4], f[5]))
        except (ValueError, IndexError):
            continue
    return rows


def install_hint(tool: str) -> str:
    if MACOS:
        return f"brew install {tool}"
    return (f"install {tool} with your package manager, e.g. "
            f"sudo apt install {tool}")
