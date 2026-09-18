#!/usr/bin/env bash
# AetherLink Linux deploy (personal, from scratch).
# Installs the PUBLISHED hosts from dist/ (see scripts/run_*_ubuntu.sh),
# snapshots DNS before first up, and leaves idempotent cleanup behind.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/opt/aetherlink}"
STATE_DIR="/var/lib/aetherlink"
STATE_FILE="$STATE_DIR/state.json"

install -d "$PREFIX/server" "$PREFIX/client" "$STATE_DIR"
install -m 0755 "$ROOT/dist/ubuntu-server/AetherLink.Server" "$PREFIX/server/"
cp -f "$ROOT/dist/ubuntu-server/libaetherlink_core.so" "$PREFIX/server/" 2>/dev/null || true
install -m 0755 "$ROOT/dist/ubuntu-client/AetherLink.Client" "$PREFIX/client/"
cp -f "$ROOT/dist/ubuntu-client/libaetherlink_core.so" "$PREFIX/client/" 2>/dev/null || true
for cfg in client.example.yaml server.example.yaml; do
  [ -f "$PREFIX/$cfg" ] || cp -f "$ROOT/configs/$cfg" "$PREFIX/$cfg"
done
# Copy the example server config to the live path (edit psk/listen before start).
[ -f "$PREFIX/server.yaml" ] || cp -f "$ROOT/configs/server.example.yaml" "$PREFIX/server.yaml"

# systemd unit (installed + reloaded, not started: review server.yaml first).
install -m 0644 "$ROOT/deploy/linux/aetherlink-server.service" /etc/systemd/system/
systemctl daemon-reload || true

# systemd-resolved / resolv.conf safety: snapshot current DNS before first up,
# so force_cleanup can restore it even after a crash or reboot.
if [ ! -f "$STATE_DIR/dns.snapshot" ]; then
  if command -v resolvectl >/dev/null 2>&1; then
    resolvectl status > "$STATE_DIR/dns.snapshot" 2>/dev/null || true
  else
    cp /etc/resolv.conf "$STATE_DIR/dns.snapshot" 2>/dev/null || true
  fi
fi

# Idempotent cleanup: restores routes + DNS from $STATE_FILE (tolerates absence).
if [ -x "$PREFIX/client/AetherLink.Client" ]; then
  "$PREFIX/client/AetherLink.Client" "$PREFIX/client.example.yaml" cleanup || true
fi

cat <<EOF
AetherLink installed to $PREFIX (server/ + client/).
DNS snapshot: $STATE_DIR/dns.snapshot (restored by force_cleanup from $STATE_FILE).
Next: edit $PREFIX/server.yaml (psk, listen), then:
  sudo systemctl enable --now aetherlink-server
Uninstall: ./deploy/linux/uninstall.sh
EOF
