#!/usr/bin/env bash
# Pack a no-git deploy bundle after a Linux build (run in WSL or on Linux):
#   ./scripts/run_server_ubuntu.sh server.yaml   # fills dist/
#   ./scripts/make_bundle.sh                     # -> aetherlink-ubuntu-<date>.tar.gz
#   scp aetherlink-ubuntu-*.tar.gz root@vps:/tmp/
# On the VPS (no git needed):
#   tar -xzf /tmp/aetherlink-ubuntu-*.tar.gz -C /tmp/aetherlink
#   sudo /tmp/aetherlink/deploy/linux/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

for d in dist/ubuntu-server dist/ubuntu-client configs deploy scripts docs/DEPLOY_UBUNTU.md; do
  [ -e "$d" ] || { echo "Missing $d (build first?)" >&2; exit 2; }
done

OUT="aetherlink-ubuntu-$(date +%Y%m%d).tar.gz"
tar -czf "$OUT" \
  dist/ubuntu-server dist/ubuntu-client \
  configs/server.example.yaml configs/client.example.yaml \
  deploy/linux scripts/run_server_ubuntu.sh docs/DEPLOY_UBUNTU.md
echo "Bundle: $OUT"
echo "Copy to VPS, unpack, run deploy/linux/install.sh (no git required there)."
