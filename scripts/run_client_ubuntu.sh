#!/usr/bin/env bash
# Quickstart: AetherLink client (full tunnel) on Ubuntu. Needs root/CAP_NET_ADMIN:
#   sudo ./scripts/run_client_ubuntu.sh [config]
# Builds core, publishes thin host, brings the tunnel up with sudo.
# EXIT/INT trap always runs down + force_cleanup (routes/DNS restored).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONFIG="${1:-configs/client.example.yaml}"
OUT_DIR="${OUT_DIR:-dist/ubuntu-client}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Re-run with sudo: TUN + default-route changes require root." >&2
  exit 2
fi

echo "==> Building Rust core (aetherlink-ffi cdylib, release)..."
cargo build --release -p aetherlink-ffi

echo "==> Publishing thin .NET client host (linux-x64, self-contained)..."
dotnet publish dotnet/AetherLink.Client/AetherLink.Client.csproj -c Release -r linux-x64 -o "$OUT_DIR"

echo "==> Staging core .so..."
cp -f target/release/libaetherlink_ffi.so "$OUT_DIR/libaetherlink_core.so"
if [ ! -f "$CONFIG" ]; then
  cp -f configs/client.example.yaml "$CONFIG"
fi

teardown() {
  echo "==> Restoring network/DNS (force_cleanup, idempotent)..."
  "$OUT_DIR/AetherLink.Client" "$CONFIG" cleanup || true
}
trap teardown EXIT INT TERM

echo "==> Tunnel up with $CONFIG (Ctrl+C brings it down, DNS/routes restored)..."
"$OUT_DIR/AetherLink.Client" "$CONFIG" up
