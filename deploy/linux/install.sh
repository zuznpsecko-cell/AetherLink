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
# Self-contained publish is a whole directory (runtime + dlls next to the
# apphost exe); copying just the exe yields "application does not exist".
cp -a "$ROOT/dist/ubuntu-server/." "$PREFIX/server/"
cp -a "$ROOT/dist/ubuntu-client/." "$PREFIX/client/"
chmod 0755 "$PREFIX/server/AetherLink.Server" "$PREFIX/client/AetherLink.Client"
for cfg in client.example.yaml server.example.yaml; do
  [ -f "$PREFIX/$cfg" ] || cp -f "$ROOT/configs/$cfg" "$PREFIX/$cfg"
done
# Copy the example server config to the live path (edit psk/listen before start).
[ -f "$PREFIX/server.yaml" ] || cp -f "$ROOT/configs/server.example.yaml" "$PREFIX/server.yaml"
# Resolve absolute TLS paths when provided (LE wildcard or self-signed);
# otherwise the service would look for ./cert.pem relative to /.
if [ -n "${TLS_CERT:-}" ] || [ -n "${TLS_KEY:-}" ]; then
  if [ -z "${TLS_CERT:-}" ] || [ -z "${TLS_KEY:-}" ]; then
    echo "Set both TLS_CERT and TLS_KEY, or neither." >&2
    exit 2
  fi
  sed -i "s|^\(\s*tls_cert:\).*|\1 \"$TLS_CERT\"|; s|^\(\s*tls_key:\).*|\1 \"$TLS_KEY\"|" \
    "$PREFIX/server.yaml"
fi

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
