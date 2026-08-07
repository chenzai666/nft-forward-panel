#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source <(sed '/^check_root$/d; /^main_menu$/d' "$ROOT_DIR/nft.sh")

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

PANEL_CERT_LEGACY_DEFAULT="$TEST_DIR/root/ygkkkca/cert.crt"
PANEL_KEY_LEGACY_DEFAULT="$TEST_DIR/root/ygkkkca/private.key"
PANEL_CERT_DEFAULT="$TEST_DIR/etc/panel-ssl/nft-ip-cert.crt"
PANEL_KEY_DEFAULT="$TEST_DIR/etc/panel-ssl/nft-ip-private.key"
PANEL_SERVICE="nft-forward-panel.service"
ACME_RENEW_HOOK="$TEST_DIR/nft-forward-acme-hook"

mkdir -p "$(dirname "$PANEL_CERT_LEGACY_DEFAULT")"
printf '%s\n' 'legacy certificate' > "$PANEL_CERT_LEGACY_DEFAULT"
printf '%s\n' 'legacy private key' > "$PANEL_KEY_LEGACY_DEFAULT"

cert_pair=$(migrate_legacy_panel_certificate "$PANEL_CERT_LEGACY_DEFAULT" "$PANEL_KEY_LEGACY_DEFAULT")
[[ "$cert_pair" == "${PANEL_CERT_DEFAULT}|${PANEL_KEY_DEFAULT}" ]]
cmp -s "$PANEL_CERT_LEGACY_DEFAULT" "$PANEL_CERT_DEFAULT"
cmp -s "$PANEL_KEY_LEGACY_DEFAULT" "$PANEL_KEY_DEFAULT"

rm -f "$PANEL_KEY_DEFAULT"
if migrate_legacy_panel_certificate "$PANEL_CERT_LEGACY_DEFAULT" "$PANEL_KEY_LEGACY_DEFAULT"; then
    echo '目标证书路径不完整时不应继续迁移。' >&2
    exit 1
fi
rm -f "$PANEL_CERT_DEFAULT"

mkdir -p "$TEST_DIR/acme/1.1.1.1"
ACME_BIN="$TEST_DIR/acme/acme.sh"
ACME_CONF="$TEST_DIR/acme/1.1.1.1/1.1.1.1.conf"
touch "$ACME_BIN"
chmod +x "$ACME_BIN"
cat > "$ACME_CONF" <<'EOF'
Le_RealKeyPath='/root/ygkkkca/private.key'
Le_RealFullChainPath='/root/ygkkkca/cert.crt'
Le_ReloadCmd='systemctl restart nft-forward-panel.service'
EOF

configure_existing_acme_renew_hooks "$ACME_BIN" '1.1.1.1' "$PANEL_CERT_DEFAULT" "$PANEL_KEY_DEFAULT"

grep -qF "Le_RealKeyPath='${PANEL_KEY_DEFAULT}'" "$ACME_CONF"
grep -qF "Le_RealFullChainPath='${PANEL_CERT_DEFAULT}'" "$ACME_CONF"
grep -qF "Le_ReloadCmd='systemctl restart ${PANEL_SERVICE}'" "$ACME_CONF"
grep -q '^Le_PreHook=' "$ACME_CONF"
grep -q '^Le_PostHook=' "$ACME_CONF"

echo 'certificate path migration tests passed'
