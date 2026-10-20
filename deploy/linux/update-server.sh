#!/usr/bin/env bash
# AetherLink server updater: refresh binaries + ad-blocklist on an
# installed VPS. Run ON the VPS as root. Kept as-is: server.yaml (PSK),
# certs, firewall and the systemd unit. The blocklist refresh is
# best-effort (old file/seed on failure) and needs a service restart
# below to take effect (included).
#
#   sudo bash deploy/linux/update-server.sh
#
# Repo is re-cloned fresh (or set REPO_DIR to reuse a checkout).
set -euo pipefail

REPO="https://github.com/zuznpsecko-cell/AetherLink.git"
WORK="${WORK:-/tmp/aetherlink-update}"
PREFIX="/opt/aetherlink"
UNIT="aetherlink-server.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)." >&2
  exit 2
fi
export DEBIAN_FRONTEND=noninteractive

# Toolchains are often user-local (rustup) while we run under sudo:
# probe the usual spots before failing with "command not found".
for d in "$HOME/.cargo/bin" /root/.cargo/bin /usr/local/cargo/bin /opt/cargo/bin; do
  [ -x "$d/cargo" ] && export PATH="$d:$PATH" && break
done
for d in "$HOME/.dotnet" /usr/share/dotnet /usr/lib/dotnet; do
  [ -x "$d/dotnet" ] && export PATH="$d:$PATH" && break
done
command -v cargo >/dev/null || { echo "cargo not found (tried ~/.cargo/bin, /root/.cargo/bin, /usr/local/cargo/bin). Install rustup first." >&2; exit 3; }
command -v dotnet >/dev/null || { echo "dotnet not found. Install .NET SDK 8+ first." >&2; exit 3; }

echo "==> [1/4] Fetch latest main..."
rm -rf "$WORK"
git clone --quiet --depth 1 "$REPO" "$WORK"
cd "$WORK"
git rev-parse --short HEAD

echo "==> [2/4] Release build (Rust core + self-contained server)..."
cargo build --release -p aetherlink-ffi
dotnet publish dotnet/AetherLink.Server/AetherLink.Server.csproj \
  -c Release -r linux-x64 --self-contained -o dist/ubuntu-server
cp -f target/release/libaetherlink_ffi.so dist/ubuntu-server/libaetherlink_core.so

echo "==> [3/5] Ad blocklist refresh (best-effort; old file kept on failure)..."
BL="$PREFIX/blocklist-ads.txt"
if bash "$WORK/scripts/fetch-blocklist.sh" "$BL" >/dev/null 2>&1; then
  if grep -qE '^[[:space:]]*#?[[:space:]]*blocked_domains_file:' "$PREFIX/server.yaml"; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*blocked_domains_file:.*|  blocked_domains_file: \"$BL\"|" "$PREFIX/server.yaml"
  else
    printf '\n  blocked_domains_file: "%s"\n' "$BL" >> "$PREFIX/server.yaml"
  fi
  echo "Blocklist refreshed ($BL)."
else
  echo "Blocklist refresh failed (offline?); keeping the old file/seed."
fi

echo "==> [4/5] Restage $PREFIX/server (stop first: ETXTBSY)..."
systemctl stop "$UNIT" 2>/dev/null || true
cp -a dist/ubuntu-server/. "$PREFIX/server/"
chmod 0755 "$PREFIX/server/AetherLink.Server"

echo "==> [5/5] Start + verify..."
systemctl start "$UNIT"
sleep 2
systemctl is-active "$UNIT"
echo "OK: $(git rev-parse --short HEAD) live."
