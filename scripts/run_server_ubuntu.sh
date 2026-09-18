#!/usr/bin/env bash
# Quickstart: AetherLink server on Ubuntu.
# One command from repo root: ./scripts/run_server_ubuntu.sh [config]
# Builds the Rust core (cdylib), publishes the thin .NET host self-contained,
# stages config + static fallback dir, then runs. Ctrl+C stops (host disposes).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CONFIG="${1:-configs/server.example.yaml}"
OUT_DIR="${OUT_DIR:-dist/ubuntu-server}"
# Provisioned LE paths (see scripts/provision_cert_ubuntu.sh); empty = keep config as-is.
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"

echo "==> Building Rust core (aetherlink-ffi cdylib, release)..."
cargo build --release -p aetherlink-ffi

echo "==> Publishing thin .NET server host (linux-x64, self-contained)..."
dotnet publish dotnet/AetherLink.Server/AetherLink.Server.csproj -c Release -r linux-x64 -o "$OUT_DIR"

echo "==> Staging core .so + config..."
cp -f target/release/libaetherlink_ffi.so "$OUT_DIR/libaetherlink_core.so"
if [ ! -f "$CONFIG" ]; then
  cp -f configs/server.example.yaml "$CONFIG"
fi
mkdir -p "$OUT_DIR/fallback"
if [ ! -f "$OUT_DIR/fallback/index.html" ]; then
  echo "<html><body>AetherLink</body></html>" > "$OUT_DIR/fallback/index.html"
fi
if [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
  if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; then
    echo "Set both TLS_CERT and TLS_KEY, or neither." >&2
    exit 2
  fi
  [ -r "$TLS_CERT" ] || { echo "TLS_CERT not readable: $TLS_CERT" >&2; exit 2; }
  [ -r "$TLS_KEY" ] || { echo "TLS_KEY not readable: $TLS_KEY" >&2; exit 2; }
  # Resolve a staged copy so the repo example stays untouched.
  STAGED="$OUT_DIR/server.yaml"
  cp -f "$CONFIG" "$STAGED"
  sed -i "s|^\(\s*tls_cert:\).*|\1 \"$TLS_CERT\"|; s|^\(\s*tls_key:\).*|\1 \"$TLS_KEY\"|" "$STAGED"
  CONFIG="$STAGED"
  echo "==> TLS paths resolved from env into $STAGED"
elif [ ! -f ./cert.pem ] || [ ! -f ./key.pem ]; then
  echo "WARNING: no TLS cert/key (./cert.pem + ./key.pem, or TLS_CERT/TLS_KEY env)." >&2
  echo "  For selmedia.ru: sudo ./scripts/provision_cert_ubuntu.sh" >&2
fi

echo "==> Running server with $CONFIG (Ctrl+C to stop)..."
exec "$OUT_DIR/AetherLink.Server" "$CONFIG"
