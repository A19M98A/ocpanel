#!/usr/bin/env bash
# Install ocpanel into ~/.local/share/ocpanel with its own virtualenv,
# and drop an `ocpanel` launcher into ~/.local/bin. Works on macOS and Linux.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$HOME/.local/share/ocpanel"
BIN="$HOME/.local/bin"

# ---------------------------------------------------------------- platform
case "$(uname -s)" in
  Darwin) OS=macos ;;
  Linux)  OS=linux ;;
  *) echo "ocpanel runs on macOS and Linux; this is $(uname -s)." >&2; exit 1 ;;
esac

# How to tell the user to install something, in the words of their own system.
if [ "$OS" = macos ]; then
  install_hint() { echo "brew install $1"; }
elif command -v apt-get >/dev/null; then
  install_hint() { echo "sudo apt install $1"; }
elif command -v dnf >/dev/null; then
  install_hint() { echo "sudo dnf install $1"; }
elif command -v pacman >/dev/null; then
  install_hint() { echo "sudo pacman -S $1"; }
elif command -v zypper >/dev/null; then
  install_hint() { echo "sudo zypper install $1"; }
else
  install_hint() { echo "install $1 with your package manager"; }
fi

# Debian and friends call it libsecret-tools; everyone else, libsecret.
secret_pkg() { if command -v apt-get >/dev/null; then echo libsecret-tools
               else echo libsecret; fi; }

need() {               # need <command> <package> [optional]
  command -v "$1" >/dev/null && return 0
  if [ "${3:-}" = optional ]; then
    echo "  note: $1 is not installed - $(install_hint "$2")"
    return 0
  fi
  echo "$1 is not installed. $(install_hint "$2")" >&2
  exit 1
}

need openconnect openconnect
need curl curl
if [ "$OS" = linux ]; then
  # The panel edits the routing table with `ip`, and reads DNS from resolvectl
  # when systemd-resolved is in charge.
  need ip iproute2
  need resolvectl systemd-resolved optional
  need secret-tool "$(secret_pkg)" optional
fi
need sing-box sing-box optional        # only for VLESS / VMess / Trojan links

echo "installing to $PREFIX ($OS)"
mkdir -p "$PREFIX/ocpanel" "$BIN"
# When install.sh sits inside the install directory itself, the sources are
# already in place - copying would delete them and then have nothing to copy.
if [ "$SRC" = "$PREFIX" ]; then
  echo "sources are already in place, skipping copy"
  SKIP_COPY=1
fi
# Copy the sources in place rather than replacing the directory: running the
# panel under sudo can leave a root-owned __pycache__ behind that a plain
# `rm -rf` cannot remove, which would break the upgrade half way through.
if [ -z "${SKIP_COPY:-}" ]; then
  rm -f "$PREFIX"/ocpanel/*.py "$PREFIX"/ocpanel/*.tcss
  cp "$SRC"/ocpanel/*.py "$SRC"/ocpanel/*.tcss "$PREFIX/ocpanel/"
fi
# Stale root-owned .pyc files are ignored by Python once the .py is newer, but
# clear them when we can so nothing confusing is left lying around.
rm -rf "$PREFIX/ocpanel/__pycache__" 2>/dev/null || true

if [ ! -x "$PREFIX/venv/bin/python" ]; then
  python3 -m venv "$PREFIX/venv" || {
    echo "could not create a virtualenv. $(install_hint python3-venv)" >&2; exit 1; }
fi
"$PREFIX/venv/bin/pip" -q install --upgrade pip
"$PREFIX/venv/bin/pip" -q install "textual>=1.0"

cat > "$BIN/ocpanel" <<LAUNCH
#!/usr/bin/env bash
# The panel needs root to alter the routing table. It reads its config from the
# invoking user's home even under sudo, so both work and share one config.
# Do not write .pyc as root - that leaves root-owned files in a user directory.
export PYTHONDONTWRITEBYTECODE=1
exec "$PREFIX/venv/bin/python" -m ocpanel "\$@"
LAUNCH
chmod +x "$BIN/ocpanel"
# Let the venv find the package no matter the working directory.
echo "$PREFIX" > "$PREFIX/venv/lib/$("$PREFIX/venv/bin/python" -c 'import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")')/site-packages/ocpanel.pth"

# Seed the config from a currently running openconnect, if there is one.
CFG="$HOME/.config/ocpanel/config.json"
if [ ! -f "$CFG" ]; then
  mkdir -p "$(dirname "$CFG")"
  "$PREFIX/venv/bin/python" - "$CFG" <<'PY'
import json, sys
from ocpanel import netinfo
sessions = netinfo.openconnect_sessions()
s = sessions[0] if sessions else None
cfg = {"profile": {"server": s.server if s else "", "user": s.user if s else "",
                   "extra_args": [], "auth_command": ""},
       "rules": []}
open(sys.argv[1], "w").write(json.dumps(cfg, indent=2) + "\n")
print(f"  seeded config from running session: {cfg['profile']['server'] or '(none found)'}")
PY
fi

echo
echo "installed. run it with:"
echo "    sudo ~/.local/bin/ocpanel   # full control (needs root to change routes)"
echo "    ocpanel                     # read-only view"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) if [ "$OS" = macos ] || [ -n "${ZSH_VERSION:-}" ]; then RC="$HOME/.zshrc"
     else RC="$HOME/.bashrc"; fi
     echo; echo "note: $BIN is not on your PATH. Add to $RC:"
     echo "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
