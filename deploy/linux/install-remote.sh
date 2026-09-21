#!/usr/bin/env bash
# AetherLink one-command installer for fresh Ubuntu (22.04/24.04), à la 3x-ui:
#   bash <(curl -Ls https://raw.githubusercontent.com/zuznpsecko-cell/AetherLink/main/deploy/linux/install-remote.sh)
#
# Asks for the domain and (optionally) a Cloudflare DNS token up front, then
# does everything from zero: dependencies (Rust, .NET SDK, build tools),
# repo checkout, release build + publish, TLS identity (LE wildcard via
# Cloudflare, or self-signed), random PSK, install to /opt/aetherlink,
# systemd unit, firewall, start.
# Non-interactive mirror of the prompts: DOMAIN=.. CLOUDFLARE_API_TOKEN=..
# in env, plus --yes to skip the final confirmation.
# Re-running is safe: binaries refresh, existing server.yaml (PSK!) is kept.
set -euo pipefail

REPO="https://github.com/zuznpsecko-cell/AetherLink.git"
WORK="${WORK:-/tmp/aetherlink-install}"
PREFIX="/opt/aetherlink"
STATE_DIR="/var/lib/aetherlink"
DOMAIN="${DOMAIN:-}"
CF_TOKEN="${CLOUDFLARE_API_TOKEN:-}"
ASSUME_YES=0
if [ "${1:-}" = "--yes" ] || [ "${1:-}" = "-y" ]; then
  ASSUME_YES=1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo)." >&2
  exit 2
fi
export DEBIAN_FRONTEND=noninteractive

# --- Interactive setup: domain + token asked BEFORE anything is installed.
# (stdin stays a TTY with the bash <(...) form, so read works here.)
if [ ! -t 0 ]; then
  if [ -z "$DOMAIN" ]; then
    echo "No TTY and DOMAIN is empty: rerun with DOMAIN=<domain> in env." >&2
    exit 2
  fi
else
  if [ -z "$DOMAIN" ]; then
    read -rp "Domain for the server (empty = self-signed cert): " DOMAIN || true
  fi
  if [ -z "$CF_TOKEN" ]; then
    read -rsp "Cloudflare API token, Zone:DNS:Edit (empty = self-signed cert): " CF_TOKEN || true
    echo
  fi
  if [ -n "$CF_TOKEN" ] && [ -z "$DOMAIN" ]; then
    echo "A token without a domain is useless: set DOMAIN too." >&2
    exit 2
  fi
  if [ "$ASSUME_YES" -ne 1 ]; then
    if [ -n "$CF_TOKEN" ]; then
      echo "Will install for domain '$DOMAIN' with a Let's Encrypt wildcard."
    elif [ -n "$DOMAIN" ]; then
      echo "Will install for domain '$DOMAIN' with a self-signed cert."
    else
      echo "Will install with a self-signed cert (CN aetherlink.local)."
    fi
    read -rp "Proceed? [Y/n] " CONFIRM || true
    case "${CONFIRM:-Y}" in
      [Yy]*|"") ;;
      *) echo "Aborted."; exit 0 ;;
    esac
  fi
fi

echo "==> [1/8] Base dependencies..."
apt update
apt install -y --no-install-recommends git curl build-essential openssl ca-certificates \
  lsb-release wget ufw

echo "==> [2/8] Rust toolchain..."
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
export PATH="$HOME/.cargo/bin:$PATH"

echo "==> [3/8] .NET SDK 10 (Microsoft repo)..."
if ! command -v dotnet >/dev/null 2>&1; then
  UBUNTU_VERSION="$(lsb_release -rs)"
  wget -q "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb" \
    -O /tmp/packages-microsoft-prod.deb
  dpkg -i /tmp/packages-microsoft-prod.deb
  apt update
  apt install -y dotnet-sdk-10.0
fi

echo "==> [4/8] Sources..."
if [ -d "$WORK/.git" ]; then
  git -C "$WORK" fetch --quiet origin
  git -C "$WORK" reset --quiet --hard origin/main
else
  rm -rf "$WORK"
  git clone --quiet --depth 1 "$REPO" "$WORK"
fi
cd "$WORK"

echo "==> [5/8] Release build (Rust core + self-contained server)..."
cargo build --release -p aetherlink-ffi
dotnet publish dotnet/AetherLink.Server/AetherLink.Server.csproj \
  -c Release -r linux-x64 --self-contained -o dist/ubuntu-server
cp -f target/release/libaetherlink_ffi.so dist/ubuntu-server/libaetherlink_core.so

echo "==> [6/8] Install to $PREFIX..."
install -d "$PREFIX/server" "$STATE_DIR"
# Full publish dir (see install.sh): the apphost exe alone won't run.
cp -a dist/ubuntu-server/. "$PREFIX/server/"
chmod 0755 "$PREFIX/server/AetherLink.Server"
mkdir -p "$PREFIX/server/fallback"
[ -f "$PREFIX/server/fallback/index.html" ] || \
  echo "<html><body>AetherLink</body></html>" > "$PREFIX/server/fallback/index.html"

echo "==> [7/9] TLS identity (Cloudflare wildcard or self-signed)..."

issue_letsencrypt() {
  # $1 = domain. Assumes certbot + plugin installed, CLOUDFLARE_API_TOKEN set.
  apt install -y --no-install-recommends certbot python3-certbot-dns-cloudflare
  install -d -m 0700 /etc/letsencrypt
  printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > /etc/letsencrypt/cloudflare.ini
  chmod 600 /etc/letsencrypt/cloudflare.ini
  certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    --dns-cloudflare-propagation-seconds 30 \
    --cert-name "$1-wildcard" --keep-until-expiring \
    --non-interactive --agree-tos --register-unsafely-without-email \
    -d "$1" -d "*.$1"
}

CERT_PEM=""
KEY_PEM=""
CERT_NOTE=""
if [ -n "$CF_TOKEN" ]; then
  if [ -z "$DOMAIN" ]; then
    echo "CLOUDFLARE_API_TOKEN is set but DOMAIN is empty." >&2
    exit 2
  fi
  issue_letsencrypt "$DOMAIN"
  CERT_PEM="/etc/letsencrypt/live/$DOMAIN-wildcard/fullchain.pem"
  KEY_PEM="/etc/letsencrypt/live/$DOMAIN-wildcard/privkey.pem"
  CERT_NOTE="public-trust Let's Encrypt wildcard (auto-renewed by certbot timer; restart service after renewal)"
else
  CN="${DOMAIN:-aetherlink.local}"
  install -d -m 0700 "$PREFIX/certs"
  if [ ! -f "$PREFIX/certs/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$PREFIX/certs/key.pem" -out "$PREFIX/certs/cert.pem" \
      -days 825 -subj "/CN=$CN" \
      -addext "subjectAltName=DNS:$CN" 2>/dev/null
    chmod 600 "$PREFIX/certs/key.pem"
  fi
  CERT_PEM="$PREFIX/certs/cert.pem"
  KEY_PEM="$PREFIX/certs/key.pem"
  CERT_NOTE="self-signed (client must pin/trust it, or rerun with CLOUDFLARE_API_TOKEN)"
fi

echo "==> [8/9] Server config..."
if [ ! -f "$PREFIX/server.yaml" ]; then
  PSK="$(openssl rand -base64 32)"
  sed -e 's|^\(\s*listen:\).*|\1 "0.0.0.0:443"|' \
      -e "s|^\(\s*psk:\).*|\1 \"$PSK\"|" \
      -e "s|^\(\s*tls_cert:\).*|\1 \"$CERT_PEM\"|" \
      -e "s|^\(\s*tls_key:\).*|\1 \"$KEY_PEM\"|" \
      -e "s|^\(\s*local_static_root:\).*|\1 \"$PREFIX/server/fallback\"|" \
      configs/server.example.yaml > "$PREFIX/server.yaml"
  chmod 600 "$PREFIX/server.yaml"
  echo "Generated fresh PSK (saved only in $PREFIX/server.yaml)."
else
  echo "Keeping existing $PREFIX/server.yaml (PSK preserved)."
fi
echo "==> [9/9] Service + firewall + start..."
install -m 0644 deploy/linux/aetherlink-server.service /etc/systemd/system/
systemctl daemon-reload
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 443/tcp comment 'AetherLink' || true
fi
systemctl enable --now aetherlink-server
sleep 3
systemctl is-active --quiet aetherlink-server || {
  echo "Service failed to start, recent logs:" >&2
  journalctl -u aetherlink-server -n 30 --no-pager >&2 || true
  exit 1
}

IP="$(curl -s --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')"
STORED_PSK="$(sed -n 's/^\s*psk:\s*"\(.*\)"/\1/p' "$PREFIX/server.yaml" | head -n 1)"
SNI="${DOMAIN:-$IP}"
cat <<EOF

================ AetherLink installed ================
Server : $IP:443 (systemd: aetherlink-server, active)
Config : $PREFIX/server.yaml | TLS: $CERT_PEM
Client config (client.yaml):
  server_addr: "$IP:443"
  outer_sni: "$SNI"
  psk: "$STORED_PSK"
NOTE: $CERT_NOTE
======================================================
EOF
