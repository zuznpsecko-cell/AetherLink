#!/usr/bin/env bash
# AetherLink server updater, incremental variant of update-server.sh.
# Same job: refresh binaries + ad-blocklist on an installed VPS, run ON the
# VPS as root; kept as-is: server.yaml (PSK), certs, firewall and the
# systemd unit; the blocklist refresh is best-effort (old file/seed on
# failure) and takes effect with the restart below. The difference:
# third-party code is compiled once instead of on every update
# (update-server.sh stays the always-from-scratch variant, in /tmp).
#
#   sudo bash deploy/linux/update-server-cached.sh           # incremental build
#   sudo bash deploy/linux/update-server-cached.sh --clean   # drop the cache, full rebuild
# After the first run the latest copy of this script always sits in
# /var/cache/aetherlink/src/deploy/linux/ (safe to run from there).
#
# All state lives in $CACHE_DIR (default /var/cache/aetherlink, survives
# reboots unlike /tmp):
#   src/           checkout, updated in place (fetch + reset --hard), not
#                  re-cloned: unchanged files keep their mtime, so cargo only
#                  rebuilds the workspace crates that really changed;
#   cargo-target/  CARGO_TARGET_DIR: compiled dependencies (tokio, rustls,
#                  aws-lc-sys, ring, ...) are reused while Cargo.lock and the
#                  toolchain stay the same;
#   out/           last good build: .NET publish + libaetherlink_core.so;
#   out.stamp      its key (commit + build recipe + toolchain versions). Same
#                  key = cargo and dotnet are not run at all, out/ is reused.
# cargo-target/ is wiped once it outgrows CACHE_MAX_MB (old crate versions
# pile up across Cargo.lock bumps); the build after that is a full one.
set -euo pipefail

REPO="https://github.com/zuznpsecko-cell/AetherLink.git"
BRANCH="${BRANCH:-main}"
CACHE_DIR="${CACHE_DIR:-/var/cache/aetherlink}"
WORK="${WORK:-$CACHE_DIR/src}"
CACHE_MAX_MB="${CACHE_MAX_MB:-4096}"
PREFIX="/opt/aetherlink"
UNIT="aetherlink-server.service"
OUT="$CACHE_DIR/out"
STAMP="$CACHE_DIR/out.stamp"
export CARGO_TARGET_DIR="$CACHE_DIR/cargo-target"

CLEAN=0
case "${1:-}" in
  "") ;;
  --clean) CLEAN=1 ;;
  *) echo "Usage: $0 [--clean]" >&2; exit 2 ;;
esac

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

# One run at a time: checkout, out/ and the stamp are shared state.
# Commands that may leave daemons behind get `9>&-` (dotnet keeps
# MSBuild/compiler servers alive for minutes, git can detach `gc --auto`),
# otherwise they would inherit fd 9 and hold the lock after we exit.
install -d -m 0755 "$CACHE_DIR"
exec 9>"$CACHE_DIR/.lock"
flock -n 9 || { echo "Another update is running (lock: $CACHE_DIR/.lock)." >&2; exit 4; }

if [ "$CLEAN" -eq 1 ]; then
  echo "==> --clean: dropping the build cache in $CACHE_DIR (full rebuild)..."
  rm -rf "$WORK" "$WORK.new" "$CARGO_TARGET_DIR" "$OUT" "$OUT.new" "$STAMP"
fi

echo "==> [1/5] Fetch latest $BRANCH..."
# In place (see header). If the old checkout is missing or broken: fresh
# clone, swapped in only once it succeeded (offline = old tree untouched).
if ! { [ -d "$WORK/.git" ] \
  && git -C "$WORK" remote set-url origin "$REPO" \
  && git -C "$WORK" fetch --quiet --depth 1 origin "$BRANCH" 9>&- \
  && git -C "$WORK" reset --quiet --hard FETCH_HEAD \
  && git -C "$WORK" clean -ffdxq; }; then
  echo "No usable checkout in $WORK (first run or failed update): fresh clone..."
  rm -rf "$WORK.new"
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$WORK.new" 9>&-
  rm -rf "$WORK"
  mv "$WORK.new" "$WORK"
fi
cd "$WORK"
git rev-parse --short HEAD

echo "==> [2/5] Release build (Rust core + self-contained server)..."
CARGO_ARGS=(build --release -p aetherlink-ffi)
PUBLISH_ARGS=(publish dotnet/AetherLink.Server/AetherLink.Server.csproj
  -c Release -r linux-x64 --self-contained)
# Everything the binaries depend on: sources (the commit), the recipe,
# toolchains (a rustup/SDK update must rebuild) and cargo/rustc env knobs
# such as CARGO_PROFILE_RELEASE_LTO. Only the hash is stored.
BUILD_KEY="$(
  {
    git rev-parse HEAD
    echo "cargo ${CARGO_ARGS[*]} | dotnet ${PUBLISH_ARGS[*]}"
    rustc -vV
    cargo -V
    dotnet --version
    env | grep -E '^(CARGO|RUST)' | sort || true
  } 2>/dev/null | sha256sum | cut -d' ' -f1
)"
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$BUILD_KEY" ] \
  && [ -x "$OUT/AetherLink.Server" ] && [ -f "$OUT/libaetherlink_core.so" ]; then
  echo "Same commit + toolchains as the last build: cargo/dotnet skipped, reusing $OUT."
else
  CACHE_MB="$(du -sm "$CARGO_TARGET_DIR" 2>/dev/null | cut -f1 || true)"
  if [ "${CACHE_MB:-0}" -gt "$CACHE_MAX_MB" ]; then
    echo "Cargo cache is $CACHE_MB MB (> CACHE_MAX_MB=$CACHE_MAX_MB): pruning it, this build is a full one."
    rm -rf "$CARGO_TARGET_DIR"
  fi
  # Dependencies already in $CARGO_TARGET_DIR are reused, not recompiled.
  cargo "${CARGO_ARGS[@]}" 9>&-
  rm -rf "$OUT.new"
  dotnet "${PUBLISH_ARGS[@]}" -o "$OUT.new" 9>&-
  cp -f "$CARGO_TARGET_DIR/release/libaetherlink_ffi.so" "$OUT.new/libaetherlink_core.so"
  # Stamp goes first and comes back last: a crash in between costs a
  # rebuild, it can never pair an old key with new binaries.
  rm -f "$STAMP"
  rm -rf "$OUT"
  mv "$OUT.new" "$OUT"
  printf '%s\n' "$BUILD_KEY" > "$STAMP"
fi

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
cp -a "$OUT/." "$PREFIX/server/"
chmod 0755 "$PREFIX/server/AetherLink.Server"

echo "==> [5/5] Start + verify..."
systemctl start "$UNIT"
sleep 2
systemctl is-active "$UNIT"
echo "OK: $(git rev-parse --short HEAD) live."
