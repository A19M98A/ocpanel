"""Read-only inspection of the macOS routing table, interfaces and openconnect."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field

TUNNEL_PREFIXES = ("utun", "ppp", "ipsec", "tun")


def _run_as_user(cmd: list[str], timeout: float = 10.0) -> str:
    """Run a command as the human who started the panel.

    NetworkExtension VPN configurations live in the user's own preferences, so
    `scutil --nc` run as root (under sudo) sees nothing. Same trick as keychain.py.
    """
    out = ""
    if os.geteuid() == 0:
        user = os.environ.get("SUDO_USER")
        if user:
            out = _run(["sudo", "-u", user, *cmd], timeout)
    return out or _run(cmd, timeout)


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (subprocess.SubprocessError, OSError):
        return ""


def is_tunnel(iface: str) -> bool:
    return iface.startswith(TUNNEL_PREFIXES)


@dataclass
class Link:
    """One default route: where traffic goes and over which interface."""
    gateway: str
    iface: str

    @property
    def tunnelled(self) -> bool:
        return is_tunnel(self.iface)


def default_routes() -> list[Link]:
    out = _run(["netstat", "-rn", "-f", "inet"])
    links: list[Link] = []
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 4 and f[0] == "default":
            gw, iface = f[1], f[-1]
            if iface.isdigit() or "." in iface:      # Expire column present
                iface = f[-2]
            links.append(Link(gw, iface))
    return links


def physical_link() -> Link | None:
    """The default route that does NOT go through a tunnel - our bypass path."""
    for link in default_routes():
        if not link.tunnelled:
            return link
    return None


def tunnel_link() -> Link | None:
    for link in default_routes():
        if link.tunnelled:
            return link
    return None


def iface_addr(iface: str) -> str:
    out = _run(["ifconfig", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return m.group(1) if m else ""


def route_iface(target: str) -> str:
    """Which interface the kernel would actually use for `target` right now."""
    out = _run(["route", "-n", "get", target])
    m = re.search(r"^\s*interface:\s*(\S+)", out, re.M)
    return m.group(1) if m else ""


def iface_bytes(iface: str) -> tuple[int, int]:
    """(rx, tx) byte counters for an interface.

    Point-to-point links (utun) have no hardware address, so the Address column
    is missing and the fixed column numbers shift. The trailing columns are
    stable on both, so index from the end of the <Link#..> row.
    """
    out = _run(["netstat", "-I", iface, "-b", "-n"])
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[0] == iface and f[2].startswith("<Link"):
            try:
                return int(f[-5]), int(f[-2])
            except (ValueError, IndexError):
                continue
    return 0, 0


@dataclass
class Session:
    pid: int
    server: str
    user: str
    argv: list[str] = field(default_factory=list)
    started: float = 0.0


def openconnect_sessions() -> list[Session]:
    """Find running openconnect processes, skipping the sudo wrappers."""
    out = _run(["ps", "-axo", "pid=,lstart=,command="])
    found: list[Session] = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\w{3} \w{3} +\d+ [\d:]+ \d{4})\s+(.*)$", line)
        if not m:
            continue
        pid, when, cmd = int(m.group(1)), m.group(2), m.group(3)
        argv = cmd.split()
        exe = argv[0].rsplit("/", 1)[-1] if argv else ""
        if exe == "sudo":                      # report the real process, not the wrapper
            continue
        if exe != "openconnect":
            continue
        user, server = "", ""
        for i, a in enumerate(argv[1:], 1):
            if a in ("-u", "--user") and i + 1 < len(argv):
                user = argv[i + 1]
            elif a.startswith("--user="):
                user = a.split("=", 1)[1]
            elif not a.startswith("-") and argv[i - 1] not in ("-u", "--user", "--protocol", "-c", "-k"):
                server = a
        try:
            started = time.mktime(time.strptime(when, "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            started = 0.0
        found.append(Session(pid=pid, server=server, user=user, argv=argv, started=started))
    return found


def resolve(host: str) -> list[str]:
    """Resolve a hostname to its IPv4 addresses."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return []
    return sorted({i[4][0] for i in infos})


def dns_servers() -> list[str]:
    out = _run(["scutil", "--dns"])
    return sorted({m for m in re.findall(r"nameserver\[\d+\] : (\S+)", out)})


GAME_PROCESS_HINTS = ("dota", "steam", "csgo", "cs2", "hl2", "srcds", "paladins",
                      "smite", "realmroyale", "hirez", "unreal")


@dataclass
class Peer:
    """A live connection from a game/launcher process to somewhere outside."""
    process: str
    pid: int
    proto: str
    local: str
    remote: str
    port: int


def _routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_multicast
                or addr.is_link_local or addr.is_unspecified)


def live_peers(hints: tuple[str, ...] = GAME_PROCESS_HINTS) -> list[Peer]:
    """Current outbound connections belonging to game processes.

    Run as root this sees every user's sockets; unprivileged it sees only yours,
    which is still enough when the game runs as you.
    """
    out = _run(["lsof", "-i", "-n", "-P"], timeout=15.0)
    peers: dict[tuple[str, int], Peer] = {}
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 9:
            continue
        command, pid_s, proto, name = f[0], f[1], f[7], f[8]
        if not any(h in command.lower() for h in hints):
            continue
        if proto not in ("TCP", "UDP") or "->" not in name:
            continue
        local, _, remote = name.partition("->")
        host, _, port_s = remote.rpartition(":")
        if not _routable(host):
            continue
        try:
            pid, port = int(pid_s), int(port_s)
        except ValueError:
            continue
        peers.setdefault((host, port), Peer(command, pid, proto, local, host, port))
    return sorted(peers.values(), key=lambda p: (p.remote, p.port))


def route_info(target: str) -> dict[str, str]:
    """The kernel's routing decision for one address, as key/value pairs."""
    out = _run(["route", "-n", "get", target])
    info: dict[str, str] = {}
    for line in out.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in ("destination", "mask", "gateway", "interface"):
            info[key.strip()] = value.strip()
    return info


def reached_via_router(target: str) -> bool:
    """True when `target` is not on the local link, i.e. traffic to it passes a gateway.

    A resolver on your own LAN (the Wi-Fi router) answers either way; one that
    sits out on the internet is exactly what a VPN is protecting.
    """
    info = route_info(target)
    return bool(info.get("gateway")) or is_tunnel(info.get("interface", ""))


def _expand_dest(dest: str) -> ipaddress.IPv4Network | None:
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


HALF_DEFAULTS = ("0.0.0.0/1", "128.0.0.0/1")


def half_default_routes() -> dict[str, Link]:
    """The two /1 routes that together cover everything, if installed.

    They are more specific than any 'default' route, so whoever owns them owns
    all traffic that has no more specific route of its own.
    """
    out = _run(["netstat", "-rn", "-f", "inet"])
    found: dict[str, Link] = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) < 4:
            continue
        net = _expand_dest(f[0])
        if net is None or str(net) not in HALF_DEFAULTS:
            continue
        iface = f[-1]
        if iface.isdigit() or "." in iface:
            iface = f[-2]
        found[str(net)] = Link(f[1], iface)
    return found


# ---------------------------------------------------------------- providers
#
# ocpanel does not care which program built the tunnel - it works on the
# routing table. But to show what you are connected to, and to offer to
# stop/start it, it has to recognise the usual owners:
#   openconnect   a process we launched or adopted
#   ne-vpn        a macOS NetworkExtension VPN (V2Box, and most VLESS /
#                 VMess / Trojan / WireGuard clients shipped as .appex)
#   unknown       a tunnel is up, but nothing recognisable owns it

NE_LIST = re.compile(
    r'^\s*(?P<enabled>\*|\s)\s*\((?P<status>\w+)\)\s+(?P<id>\S+)\s+(?P<type>\S+)'
    r'\s+\((?P<bundle>[^)]*)\)\s+"(?P<name>[^"]*)"')


@dataclass
class NEService:
    """A VPN configuration macOS knows about, from `scutil --nc list`."""
    name: str
    status: str
    identifier: str
    bundle: str
    enabled: bool

    @property
    def connected(self) -> bool:
        return self.status.lower() == "connected"


def ne_vpn_services() -> list[NEService]:
    out = _run_as_user(["scutil", "--nc", "list"])
    found = []
    for line in out.splitlines():
        m = NE_LIST.match(line)
        if m:
            found.append(NEService(name=m["name"], status=m["status"],
                                   identifier=m["id"], bundle=m["bundle"],
                                   enabled=m["enabled"] == "*"))
    return found


@dataclass
class Provider:
    """Whatever owns the tunnel at the moment, however it was started."""
    kind: str                       # openconnect | ne-vpn | unknown
    name: str                       # what to show: "openconnect", "V2BOX" ...
    server: str = ""
    user: str = ""
    pid: int | None = None
    service: str | None = None      # NE name, for scutil --nc
    bundle: str = ""
    started: float = 0.0
    iface: str = ""
    status: str = "Connected"       # a system VPN can also be mid-connect

    @property
    def connecting(self) -> bool:
        return self.status.lower() in ("connecting", "reasserting", "disconnecting")

    @property
    def controllable(self) -> bool:
        """Can the panel stop this one, or is it someone else's business?"""
        return self.kind == "openconnect" and self.pid is not None or (
            self.kind == "ne-vpn" and bool(self.service))

    @property
    def label(self) -> str:
        if self.kind == "ne-vpn":
            return f"{self.name} (system VPN)"
        return self.name


def tunnel_provider() -> Provider | None:
    """Who is carrying the traffic right now.

    A tunnel may exist with nobody recognisable behind it - that is still
    reported, because the routing side works either way.
    """
    tunnel = tunnel_link()
    sessions = openconnect_sessions()
    if sessions:
        s = sessions[0]
        return Provider(kind="openconnect", name="openconnect", server=s.server,
                        user=s.user, pid=s.pid, started=s.started,
                        iface=tunnel.iface if tunnel else "")
    # A system VPN that is still coming up counts too: it is why the tunnel
    # blinks out for a moment, and the panel should say so rather than claim
    # nothing is connected.
    for svc in ne_vpn_services():
        if svc.connected or svc.status.lower() in ("connecting", "reasserting"):
            return Provider(kind="ne-vpn", name=svc.name, server=svc.name,
                            service=svc.name, bundle=svc.bundle,
                            status=svc.status,
                            iface=tunnel.iface if tunnel else "")
    if tunnel is not None:
        return Provider(kind="unknown", name=tunnel.iface, iface=tunnel.iface)
    return None


# ------------------------------------------------------------------- probing
#
# A route being correct does not mean the target answers over it. Some networks
# accept the TCP connection and then drop the traffic, so a plain connect test
# reports success for a site that never loads. Completing a TLS handshake is
# what separates "reachable" from "intercepted".

@dataclass
class Probe:
    ok: bool
    detail: str
    seconds: float = 0.0
    iface: str = ""


def probe(target: str, port: int = 443, timeout: float = 8.0,
          tls_host: str | None = None) -> Probe:
    """Open a real connection to `target` the way the routing table sends it."""
    import socket
    import ssl
    iface = route_iface(target)
    start = time.monotonic()
    try:
        sock = socket.create_connection((target, port), timeout=timeout)
    except OSError as exc:
        return Probe(False, f"no connection ({exc.strerror or exc})",
                     time.monotonic() - start, iface)
    try:
        if port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False          # we are testing reach, not identity
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(sock, server_hostname=tls_host or None) as tls:
                tls.do_handshake()
                return Probe(True, f"TLS ok ({tls.version()})",
                             time.monotonic() - start, iface)
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        got = sock.recv(16)
        if not got:
            return Probe(False, "connected, then no reply",
                         time.monotonic() - start, iface)
        return Probe(True, "answered", time.monotonic() - start, iface)
    except (OSError, ssl.SSLError) as exc:
        if isinstance(exc, (TimeoutError, socket.timeout)):
            # Accepted the connection and then went quiet: the signature of a
            # middlebox sitting in front of the real server.
            reason = "connected, then silence (intercepted?)"
        elif port == 443:
            reason = f"TLS handshake failed ({exc})"
        else:
            reason = f"connection dropped ({getattr(exc, 'strerror', None) or exc})"
        return Probe(False, reason, time.monotonic() - start, iface)
    finally:
        try:
            sock.close()
        except OSError:
            pass
