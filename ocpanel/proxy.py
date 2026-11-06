"""Run a VLESS/VMess/Trojan subscription as a plain tunnel, via sing-box.

Why this exists: a client shipped as a macOS NetworkExtension can set
includeAllNetworks, and then the system hands it every packet below the routing
table - no route-based split tunnelling can work against it (see netinfo.captured).
sing-box run as root creates an ordinary `utun` with ordinary routes, so
ocpanel's bypass and VPN lists apply exactly as they do with openconnect.

The subscription URL is a credential. It is kept in the login keychain, never in
config.json, and never on a command line.
"""
from __future__ import annotations

import base64
import json
import os
import re
import signal
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .config import CONFIG_DIR

CONFIG_FILE = CONFIG_DIR / "sing-box.json"
PID_FILE = CONFIG_DIR / "sing-box.pid"
LOG_FILE = CONFIG_DIR / "sing-box.log"

# Where the tunnel lives. A /30 inside the shared-address range, so it cannot
# collide with a home network.
TUN_ADDRESS = "172.19.0.1/30"
TUN_NAME = "utun"

SUPPORTED = ("vless", "vmess", "trojan")
LINK_SCHEMES = tuple(f"{s}://" for s in SUPPORTED)


def looks_like_link(text: str) -> bool:
    """A pasted server URI rather than a subscription URL."""
    return text.strip().lower().startswith(LINK_SCHEMES)


def binary() -> str | None:
    for path in ("/opt/homebrew/bin/sing-box", "/usr/local/bin/sing-box", "sing-box"):
        try:
            if subprocess.run([path, "version"], capture_output=True,
                              timeout=10).returncode == 0:
                return path
        except (OSError, subprocess.SubprocessError):
            continue
    return None


def version() -> str:
    exe = binary()
    if not exe:
        return ""
    try:
        out = subprocess.run([exe, "version"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    m = re.search(r"version (\S+)", out)
    return m.group(1) if m else out.splitlines()[0] if out else ""


# ----------------------------------------------------------------- servers

@dataclass
class Server:
    """One entry from a subscription, in the form sing-box wants."""
    name: str
    protocol: str
    host: str
    port: int
    uuid: str
    transport: str = "tcp"          # tcp | ws | grpc
    path: str = ""
    ws_host: str = ""
    tls: bool = False
    sni: str = ""
    flow: str = ""
    insecure: bool = False
    encryption: str = "none"

    @property
    def unsupported(self) -> str:
        """Why sing-box cannot run this entry, or "" if it can."""
        if self.protocol == "vless" and self.encryption not in ("", "none"):
            # Xray's post-quantum VLESS encryption (mlkem768...) has no sing-box
            # implementation; the handshake simply never completes.
            return "needs Xray (VLESS encryption)"
        if self.transport not in ("tcp", "ws", "grpc"):
            return f"transport {self.transport} not supported"
        return ""

    @property
    def label(self) -> str:
        bits = [self.protocol, self.transport]
        if self.tls:
            bits.append("tls")
        note = f"  - {self.unsupported}" if self.unsupported else ""
        return f"{self.name or self.host}  ({', '.join(bits)}, port {self.port}){note}"

    def outbound(self, tag: str = "proxy") -> dict:
        out: dict = {"type": self.protocol, "tag": tag,
                     "server": self.host, "server_port": self.port}
        if self.protocol == "trojan":
            out["password"] = self.uuid
        else:
            out["uuid"] = self.uuid
        if self.protocol == "vless" and self.flow:
            out["flow"] = self.flow
        if self.transport == "ws":
            ws: dict = {"type": "ws", "path": self.path or "/"}
            if self.ws_host:
                ws["headers"] = {"Host": self.ws_host}
            out["transport"] = ws
        elif self.transport == "grpc":
            out["transport"] = {"type": "grpc", "service_name": self.path.strip("/")}
        if self.tls:
            out["tls"] = {"enabled": True,
                          "server_name": self.sni or self.ws_host or self.host,
                          "insecure": self.insecure}
        return out


def _decode(raw: str) -> str:
    """A subscription body is usually base64; sometimes it is already plain."""
    text = raw.strip()
    if "://" in text.splitlines()[0] if text else False:
        return text
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode(errors="replace")
    except Exception:
        return text


def parse_uri(uri: str) -> Server | None:
    """Turn one vless:// / vmess:// / trojan:// line into a Server."""
    uri = uri.strip()
    scheme = uri.split("://", 1)[0].lower()
    if scheme == "vmess":
        try:
            body = uri.split("://", 1)[1]
            cfg = json.loads(base64.b64decode(body + "=" * (-len(body) % 4)))
        except Exception:
            return None
        return Server(name=str(cfg.get("ps", "")), protocol="vmess",
                      host=str(cfg.get("add", "")), port=int(cfg.get("port", 0) or 0),
                      uuid=str(cfg.get("id", "")),
                      transport=str(cfg.get("net", "tcp")),
                      path=str(cfg.get("path", "")), ws_host=str(cfg.get("host", "")),
                      tls=str(cfg.get("tls", "")).lower() in ("tls", "true"),
                      sni=str(cfg.get("sni", "")))
    if scheme not in SUPPORTED:
        return None
    m = re.match(r"\w+://(?P<cred>[^@]+)@(?P<host>[^:/?#]+):(?P<port>\d+)(?P<rest>.*)", uri)
    if not m:
        return None
    rest = m["rest"]
    query = urllib.parse.parse_qs(urllib.parse.urlparse("x://h" + rest).query)
    one = lambda k, d="": (query.get(k) or [d])[0]           # noqa: E731
    name = urllib.parse.unquote(rest.split("#", 1)[1]) if "#" in rest else ""
    security = one("security", "none").lower()
    return Server(
        name=name, protocol=scheme,
        host=m["host"], port=int(m["port"]),
        uuid=urllib.parse.unquote(m["cred"]),
        transport=one("type", "tcp").lower(),
        path=urllib.parse.unquote(one("path", "")),
        ws_host=one("host", ""),
        tls=security in ("tls", "reality", "xtls"),
        sni=one("sni", ""), flow=one("flow", ""),
        insecure=one("allowInsecure", "0") in ("1", "true"),
        encryption=one("encryption", "none"),
    )


def parse_subscription(body: str) -> list[Server]:
    servers = []
    for line in _decode(body).splitlines():
        line = line.strip()
        if not line or "://" not in line:
            continue
        srv = parse_uri(line)
        if srv and srv.host and srv.port and srv.uuid:
            servers.append(srv)
    return servers


def servers_from(kind: str, secret: str, timeout: float = 25.0) -> tuple[list[Server], str]:
    """Servers from one source, whichever kind it is."""
    if kind == "link" or looks_like_link(secret):
        srv = parse_uri(secret.strip())
        if srv is None or not (srv.host and srv.port and srv.uuid):
            return [], "that link could not be read"
        return [srv], ""
    return fetch_subscription(secret, timeout)


def fetch_subscription(url: str, timeout: float = 25.0) -> tuple[list[Server], str]:
    """Download and parse. curl, not urllib: a python.org Python has no root certs."""
    try:
        p = subprocess.run(["curl", "-fsSL", "--max-time", str(int(timeout)), url],
                           capture_output=True, text=True, timeout=timeout + 5)
    except (subprocess.SubprocessError, OSError) as exc:
        return [], str(exc)
    if p.returncode != 0:
        return [], (p.stderr.strip() or f"curl exited with status {p.returncode}")[:200]
    servers = parse_subscription(p.stdout)
    return servers, "" if servers else "nothing usable in the subscription"


# ------------------------------------------------------------------ config

def build_config(server: Server, *, socks_port: int = 0) -> dict:
    """A sing-box config that behaves like an ordinary VPN.

    No includeAllNetworks equivalent exists here: `auto_route` writes normal
    routes into the normal routing table, which is precisely what lets ocpanel's
    rules override them. `auto_detect_interface` keeps the tunnel's own traffic
    to the server from looping back into itself.
    """
    inbounds: list[dict] = []
    if socks_port:
        inbounds.append({"type": "socks", "tag": "socks-in",
                         "listen": "127.0.0.1", "listen_port": socks_port})
    else:
        # sing-box 1.11 moved sniffing out of the inbound and 1.13 removed the
        # old fields outright, so it is a route action now (see below).
        inbounds.append({
            "type": "tun", "tag": "tun-in",
            "address": [TUN_ADDRESS],
            "auto_route": True,
            "strict_route": False,        # leave the routing table ordinary
            "stack": "gvisor",
        })
    return {
        "log": {"level": "warn", "timestamp": True},
        # sing-box 1.12 replaced the old {"address": ...} DNS entries and 1.14
        # removed them outright, so this uses the typed form.
        "dns": {
            "servers": [
                {"tag": "remote", "type": "udp", "server": "1.1.1.1", "detour": "proxy"},
                {"tag": "local", "type": "udp", "server": "223.5.5.5"},
            ],
            "final": "remote",
            "strategy": "ipv4_only",
        },
        "inbounds": inbounds,
        "outbounds": [
            server.outbound("proxy"),
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "auto_detect_interface": True,
            # The proxy server's own hostname has to resolve without the proxy,
            # or the tunnel cannot come up at all.
            "default_domain_resolver": {"server": "local"},
            "final": "proxy",
            "rules": [
                {"action": "sniff"},
                {"ip_is_private": True, "outbound": "direct"},
            ],
        },
    }


def write_config(server: Server, *, socks_port: int = 0,
                 path: Path | None = None) -> Path:
    path = path or CONFIG_FILE
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_config(server, socks_port=socks_port), indent=2))
    path.chmod(0o600)                     # it holds the server credential
    return path


def check_config(path: Path) -> tuple[bool, str]:
    exe = binary()
    if not exe:
        return False, "sing-box is not installed (brew install sing-box)"
    try:
        p = subprocess.run([exe, "check", "-c", str(path)],
                           capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


# ------------------------------------------------------------------ running

@dataclass
class Run:
    ok: bool
    detail: str
    pid: int | None = None
    output: list[str] = field(default_factory=list)


def start(server: Server, *, socks_port: int = 0, wait: float = 12.0) -> Run:
    """Start sing-box in the background and wait for it to settle."""
    exe = binary()
    if not exe:
        return Run(False, "sing-box is not installed (brew install sing-box)")
    if not socks_port and os.geteuid() != 0:
        return Run(False, "a tunnel needs root - run the panel with sudo")
    path = write_config(server, socks_port=socks_port)
    ok, detail = check_config(path)
    if not ok:
        return Run(False, f"config rejected: {detail.splitlines()[-1][:160]}"
                   if detail else "config rejected")
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log = LOG_FILE.open("a")
    try:
        proc = subprocess.Popen([exe, "run", "-c", str(path)],
                                stdout=log, stderr=log, start_new_session=True)
    except OSError as exc:
        return Run(False, str(exc))
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return Run(False, f"sing-box exited with status {proc.returncode}",
                       output=tail_log())
        time.sleep(0.4)
        if socks_port or _tunnel_up():
            PID_FILE.write_text(str(proc.pid))
            return Run(True, f"running as pid {proc.pid}", pid=proc.pid)
    PID_FILE.write_text(str(proc.pid))
    return Run(True, f"started as pid {proc.pid} (still settling)", pid=proc.pid)


def _tunnel_up() -> bool:
    from . import netinfo
    link = netinfo.tunnel_link()
    return link is not None


def tail_log(lines: int = 8) -> list[str]:
    try:
        return LOG_FILE.read_text(errors="replace").splitlines()[-lines:]
    except OSError:
        return []


def running_pid() -> int | None:
    """The sing-box we started, if it is still alive."""
    try:
        pid = int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return None
    return pid


def stop(pid: int | None = None) -> tuple[bool, str]:
    pid = pid or running_pid()
    if not pid:
        return False, "sing-box is not running"
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False, f"no process {pid}"
    except PermissionError:
        return False, f"not permitted to stop {pid} - run the panel with sudo"
    for _ in range(40):
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            break
        time.sleep(0.25)
    try:
        PID_FILE.unlink()
    except OSError:
        pass
    return True, f"stopped sing-box ({pid})"
