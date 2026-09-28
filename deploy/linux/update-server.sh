#!/usr/bin/env bash
# AetherLink server updater: refresh binaries on an installed VPS.
# Run ON the VPS as root. Touches NOTHING else: server.yaml (PSK),
# certs, firewall and the systemd unit are kept as-is.
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

echo "==> [3/4] Restage $PREFIX/server (stop first: ETXTBSY)..."
systemctl stop "$UNIT" 2>/dev/null || true
cp -a dist/ubuntu-server/. "$PREFIX/server/"
chmod 0755 "$PREFIX/server/AetherLink.Server"

echo "==> [4/4] Start + verify..."
systemctl start "$UNIT"
sleep 2
systemctl is-active "$UNIT"
echo "OK: $(git rev-parse --short HEAD) live."
