#!/usr/bin/env bash
# Provision a public-trust wildcard cert for selmedia.ru via Let's Encrypt
# DNS-01 + Cloudflare API. Idempotent: skips issuance while fresh.
#
# Prerequisites (one time, Cloudflare dashboard):
#   My Profile -> API Tokens -> Create Token -> "Edit zone DNS" template,
#   zone: selmedia.ru. Save the token, it is shown only once.
#
# Usage: sudo ./scripts/provision_cert_ubuntu.sh
# Result: /etc/letsencrypt/live/selmedia.ru-wildcard/{fullchain,privkey}.pem
set -euo pipefail

DOMAIN="selmedia.ru"
LINEAGE="selmedia.ru-wildcard"
CRED="/etc/letsencrypt/cloudflare.ini"
EMAIL="${EMAIL:-}"

if [ "$(id -u)" -ne 0 ]; then
  echo "Re-run with sudo: certbot writes to /etc/letsencrypt." >&2
  exit 2
fi

if ! command -v certbot >/dev/null 2>&1; then
  echo "==> Installing certbot + Cloudflare DNS plugin..."
  apt update
  apt install -y certbot python3-certbot-dns-cloudflare
fi

if [ ! -f "$CRED" ]; then
  echo "Missing $CRED with a single line:" >&2
  echo "  dns_cloudflare_api_token = <token with Zone:DNS:Edit on $DOMAIN>" >&2
  exit 2
fi
chmod 600 "$CRED"

ARGS=(certonly --dns-cloudflare --dns-cloudflare-credentials "$CRED"
  --dns-cloudflare-propagation-seconds 30
  --cert-name "$LINEAGE" --keep-until-expiring
  --non-interactive --agree-tos
  -d "$DOMAIN" -d "*.$DOMAIN")
if [ -n "$EMAIL" ]; then
  ARGS+=(--email "$EMAIL")
else
  ARGS+=(--register-unsafely-without-email)
fi

echo "==> Issuing/renewing wildcard for $DOMAIN ..."
certbot "${ARGS[@]}"

echo "Cert:  /etc/letsencrypt/live/$LINEAGE/fullchain.pem"
echo "Key:   /etc/letsencrypt/live/$LINEAGE/privkey.pem"
echo "Point the server at them:"
echo "  TLS_CERT=/etc/letsencrypt/live/$LINEAGE/fullchain.pem \\"
echo "  TLS_KEY=/etc/letsencrypt/live/$LINEAGE/privkey.pem \\"
echo "  ./scripts/run_server_ubuntu.sh"
echo "NOTE: after each auto-renewal (certbot timer), restart the server process."
