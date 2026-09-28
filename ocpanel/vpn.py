"""Start and stop the openconnect client.

Connecting never blocks the panel: openconnect runs with --background, so it
daemonises as soon as the tunnel is up, and with --non-inter, so it exits with a
message instead of sitting at a prompt nobody can see behind the panel. The
password is handed over on stdin - it is never written to disk, into the log, or
into the command line (where `ps` would show it).
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from .config import CONFIG_DIR, Profile

PID_FILE = CONFIG_DIR / "openconnect.pid"

# What a failure line looks like. Whole words only: a server called
# "something.invalid" must not look like an error.
TROUBLE = re.compile(r"\b(failed|failure|error|denied|refused|unable|invalid|"
                     r"timeout|timed out|no such host|certificate|required|"
                     r"not known|rejected)\b", re.I)

# Routine progress chatter, never the reason for anything.
NOISE = ("post http", "connected to", "ssl negotiation", "xml post", "got ",
         "sending ", "connected as")


@dataclass
class Attempt:
    ok: bool
    summary: str
    output: list[str] = field(default_factory=list)


def build_argv(profile: Profile, *, on_stdin: bool, interactive: bool = False) -> list[str]:
    if not profile.server:
        raise ValueError("no server configured")
    argv = ["openconnect", "--background", f"--pid-file={PID_FILE}"]
    if not interactive:
        # Never wait for input nobody can answer - exit and say so instead.
        argv.append("--non-inter")
    if profile.user:
        argv += ["--user", profile.user]
    if on_stdin:
        argv.append("--passwd-on-stdin")
    argv += list(profile.extra_args)
    argv.append(profile.server)
    return argv


# openconnect ends a failure with one of these; the useful line comes earlier.
GENERIC = ("failed to complete authentication", "failed to obtain webvpn cookie",
           "failed to open https connection")


def _summarise(returncode: int, output: list[str]) -> str:
    if returncode == 0:
        return "connected"
    lines = [l.strip() for l in output
             if not any(l.strip().lower().startswith(n) for n in NOISE)]
    hits = [l for l in lines if TROUBLE.search(l)]
    specific = [l for l in hits if not any(g in l.lower() for g in GENERIC)]
    if specific:
        return specific[0]                  # the cause, not the consequence
    if hits:
        return hits[0]
    return f"openconnect exited with status {returncode}"


def connect(profile: Profile, password: str | None = None,
            timeout: float = 120.0) -> Attempt:
    """Run openconnect until it daemonises. Safe to call from a worker thread.

    `password` is used once and not kept. A profile with an auth_command uses
    that command's output instead.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    secret = password
    if profile.auth_command:
        try:
            auth = subprocess.run(["/bin/sh", "-c", profile.auth_command],
                                  capture_output=True, text=True, timeout=60)
        except (subprocess.SubprocessError, OSError) as exc:
            return Attempt(False, f"auth_command failed: {exc}")
        if auth.returncode != 0:
            return Attempt(False, f"auth_command failed: {auth.stderr.strip()[:200]}")
        secret = auth.stdout.rstrip("\n")
    argv = build_argv(profile, on_stdin=secret is not None)
    try:
        proc = subprocess.run(argv, input=(secret + "\n") if secret is not None else "",
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Attempt(False, f"openconnect did not finish within {int(timeout)}s")
    except (OSError, ValueError) as exc:
        return Attempt(False, str(exc))
    finally:
        secret = None
    output = [line for line in (proc.stdout + proc.stderr).splitlines() if line.strip()]
    return Attempt(proc.returncode == 0, _summarise(proc.returncode, output), output)


def connect_in_terminal(profile: Profile, timeout: float = 300.0) -> Attempt:
    """Hand openconnect the terminal, for a server that asks for more than a
    password (a group, a token, a certificate to accept)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    argv = build_argv(profile, on_stdin=False, interactive=True)
    try:
        proc = subprocess.run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        return Attempt(False, "openconnect timed out")
    except (OSError, ValueError) as exc:
        return Attempt(False, str(exc))
    return Attempt(proc.returncode == 0, _summarise(proc.returncode, []))


def disconnect(pid: int) -> tuple[bool, str]:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False, f"no process {pid}"
    except PermissionError:
        return False, f"not permitted to signal {pid} - run the panel with sudo"
    try:
        PID_FILE.unlink()
    except OSError:
        pass
    return True, f"sent SIGTERM to {pid}"


def wait_gone(pid: int, timeout: float = 15.0) -> bool:
    """Wait for a signalled openconnect to exit, so a reconnect does not race it."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            return True
        time.sleep(0.2)
    return False


def pid_from_file() -> int | None:
    try:
        return int(Path(PID_FILE).read_text().strip())
    except (OSError, ValueError):
        return None
