#!/usr/bin/env bash
# AetherLink Linux uninstall: exact inverse of install.sh.
# Runs cleanup first (routes/DNS restored), then removes everything,
# including state snapshots, so no traces remain.
set -euo pipefail

PREFIX="${PREFIX:-/opt/aetherlink}"
STATE_DIR="/var/lib/aetherlink"
CACHE_DIR="${CACHE_DIR:-/var/cache/aetherlink}"  # update-server.sh build cache

if [ -x "$PREFIX/client/AetherLink.Client" ]; then
  "$PREFIX/client/AetherLink.Client" "$PREFIX/client.example.yaml" cleanup || true
fi
systemctl disable --now aetherlink-server 2>/dev/null || true
rm -f /etc/systemd/system/aetherlink-server.service
systemctl daemon-reload 2>/dev/null || true
rm -rf "$PREFIX" "$STATE_DIR" "$CACHE_DIR"

echo "AetherLink uninstalled (service, binaries, configs, state and build cache removed)."
