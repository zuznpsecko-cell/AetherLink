#!/usr/bin/env bash
# Quickstart: AetherLink Linux client (full tunnel + optional WiFi hotspot)
# on Ubuntu 24.04. Needs root/CAP_NET_ADMIN:
#   sudo ./scripts/run_client_ubuntu.sh [config]
# Builds the native thin client (aetherlink-cli, links the Rust core
# directly — no protocol code outside the core), stages it into dist/, then
# brings the tunnel up. EXIT/INT trap always runs cleanup (routes/DNS
# restored, hotspot down).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONFIG="${1:-configs/client.example.yaml}"
OUT_DIR="${OUT_DIR:-dist/ubuntu-client}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Re-run with sudo: TUN + default-route changes require root." >&2
  exit 2
fi

echo "==> Building the Linux client (aetherlink-cli, release)..."
cargo build --release -p aetherlink-cli

echo "==> Staging binary..."
mkdir -p "$OUT_DIR"
cp -f target/release/aetherlink-cli "$OUT_DIR/aetherlink-cli"
if [ ! -f "$CONFIG" ]; then
  cp -f configs/client.example.yaml "$CONFIG"
fi

teardown() {
  echo "==> Restoring network/DNS (cleanup, idempotent)..."
  "$OUT_DIR/aetherlink-cli" "$CONFIG" cleanup || true
}
trap teardown EXIT INT TERM

echo "==> Tunnel up with $CONFIG (Ctrl+C brings it down, DNS/routes restored)."
echo "    WiFi clients: enable the hotspot section in the config (or run"
echo "    '$OUT_DIR/aetherlink-cli hotspot up --password ...' separately)."
# No exec: the EXIT trap above must survive to run cleanup on abnormal exits.
"$OUT_DIR/aetherlink-cli" "$CONFIG" up
