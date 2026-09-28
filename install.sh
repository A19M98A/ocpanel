#!/usr/bin/env bash
# Install ocpanel into ~/.local/share/ocpanel with its own virtualenv,
# and drop an `ocpanel` launcher into ~/.local/bin.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$HOME/.local/share/ocpanel"
BIN="$HOME/.local/bin"

command -v openconnect >/dev/null || {
  echo "openconnect is not installed. brew install openconnect" >&2; exit 1; }

echo "installing to $PREFIX"
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
  python3 -m venv "$PREFIX/venv"
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
  *) echo; echo "note: $BIN is not on your PATH. Add to ~/.zshrc:"
     echo "    export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
esac
