#!/usr/bin/env bash
# HispanShield OS — Local MISP Threat Intelligence Platform (Air-Gap Mode)
#
# Deploys MISP in a network-isolated Docker container and imports signed
# threat intelligence feeds from a GPG-encrypted USB bundle.
# Zero external dependencies: no cloud connectivity required.
#
# Usage:
#   HISPANSHIELD_TI_USB=/mnt/ti_feeds ./local_misp_setup.sh [--import-only]

set -euo pipefail

MISP_CONTAINER="misp-hispanshield"
MISP_DATA_VOL="misp-hispanshield-data"
MISP_BIND_ADDR="127.0.0.1"
MISP_PORT="8888"
FEED_USB_PATH="${HISPANSHIELD_TI_USB:-/mnt/ti_feeds}"
MISP_API_KEY_FILE="/etc/hispanshield/misp_api_key"
MISP_ADMIN_PASSPHRASE_FILE="/etc/hispanshield/secrets/misp_admin.pass"
IMPORT_ONLY="${1:-}"

log()  { echo "[MISP-TI] $*"; }
warn() { echo "[MISP-TI] WARN: $*" >&2; }
die()  { echo "[MISP-TI] FATAL: $*" >&2; exit 1; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
check_prerequisites() {
    command -v docker &>/dev/null || die "Docker not installed"
    command -v gpg   &>/dev/null || die "gpg not installed"
    command -v curl  &>/dev/null || die "curl not installed"
    [ "$(id -u)" -eq 0 ] || die "Must run as root"
}

# ── Generate admin credentials ─────────────────────────────────────────────────
generate_credentials() {
    install -d -m 700 /etc/hispanshield/secrets
    if [ ! -f "$MISP_ADMIN_PASSPHRASE_FILE" ]; then
        openssl rand -base64 48 > "$MISP_ADMIN_PASSPHRASE_FILE"
        chmod 400 "$MISP_ADMIN_PASSPHRASE_FILE"
        log "Generated MISP admin passphrase: $MISP_ADMIN_PASSPHRASE_FILE"
    fi
}

# ── Deploy MISP container ──────────────────────────────────────────────────────
setup_local_misp() {
    if docker ps -a --format '{{.Names}}' | grep -q "^${MISP_CONTAINER}$"; then
        log "MISP container already exists — skipping deploy"
        docker start "$MISP_CONTAINER" 2>/dev/null || true
        return
    fi

    log "Deploying MISP in air-gap mode (no external network)..."
    local passphrase
    passphrase=$(cat "$MISP_ADMIN_PASSPHRASE_FILE")

    docker run -d \
        --name "$MISP_CONTAINER" \
        --network none \
        --restart unless-stopped \
        -p "${MISP_BIND_ADDR}:${MISP_PORT}:80" \
        -v "${MISP_DATA_VOL}:/var/www/MISP/app/files" \
        -e MISP_ADMIN_EMAIL="aegis@hispanshield.local" \
        -e MISP_ADMIN_PASSPHRASE="$passphrase" \
        -e MISP_BASEURL="http://${MISP_BIND_ADDR}:${MISP_PORT}" \
        -e CLAMAV=false \
        -e SYSLOG=false \
        harvarditsecurity/misp:latest

    log "MISP deployed — waiting for initialisation (60s)..."
    sleep 60

    # Extract API key from container after first-run initialisation
    local api_key
    api_key=$(docker exec "$MISP_CONTAINER" \
        mysql -u misp -pmisp misp -se \
        "SELECT authkey FROM users WHERE email='admin@admin.test' LIMIT 1;" \
        2>/dev/null | tail -1 || true)
    if [ -n "$api_key" ]; then
        install -m 600 /dev/null "$MISP_API_KEY_FILE"
        echo "$api_key" > "$MISP_API_KEY_FILE"
        log "API key saved to $MISP_API_KEY_FILE"
    else
        warn "Could not extract API key — set manually after MISP initialisation"
    fi
}

# ── Import offline feed bundles ────────────────────────────────────────────────
import_offline_feeds() {
    if [ ! -d "$FEED_USB_PATH" ]; then
        warn "Feed USB path not found: $FEED_USB_PATH — skipping feed import"
        return
    fi
    if [ ! -f "$MISP_API_KEY_FILE" ]; then
        warn "MISP API key not found at $MISP_API_KEY_FILE — skipping feed import"
        return
    fi
    local api_key
    api_key=$(cat "$MISP_API_KEY_FILE")
    local misp_url="http://${MISP_BIND_ADDR}:${MISP_PORT}"

    local imported=0
    local failed=0

    log "Scanning $FEED_USB_PATH for signed feed bundles..."
    for feed_bundle in "${FEED_USB_PATH}"/*.misp.gpg; do
        [ -f "$feed_bundle" ] || continue
        log "Importing: $(basename "$feed_bundle")"

        # Verify and decrypt GPG bundle
        local decrypted
        decrypted=$(gpg --batch --decrypt "$feed_bundle" 2>/dev/null) || {
            warn "GPG decryption failed for $feed_bundle — skipping"
            failed=$((failed + 1))
            continue
        }

        # Validate that the decrypted content is valid JSON before sending
        echo "$decrypted" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null || {
            warn "Decrypted bundle is not valid JSON: $feed_bundle — skipping"
            failed=$((failed + 1))
            continue
        }

        # Push to MISP via internal loopback (container shares loopback with host)
        local response
        response=$(echo "$decrypted" | curl -sf \
            -X POST \
            -H "Authorization: $api_key" \
            -H "Content-Type: application/json" \
            -H "Accept: application/json" \
            --data-binary @- \
            "${misp_url}/events/import" 2>&1) || {
            warn "MISP import failed for $feed_bundle: $response"
            failed=$((failed + 1))
            continue
        }
        imported=$((imported + 1))
        log "Imported: $(basename "$feed_bundle")"
    done

    log "Feed import complete — imported=$imported failed=$failed"
}

# ── MISP health check ──────────────────────────────────────────────────────────
check_misp_health() {
    local misp_url="http://${MISP_BIND_ADDR}:${MISP_PORT}"
    local api_key
    api_key=$(cat "$MISP_API_KEY_FILE" 2>/dev/null || echo "")
    if [ -z "$api_key" ]; then
        warn "No API key — skipping health check"
        return
    fi
    local status
    status=$(curl -sf \
        -H "Authorization: $api_key" \
        -H "Accept: application/json" \
        "${misp_url}/servers/serverSettings.json" 2>/dev/null | \
        python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('Server',{}).get('MISP',{}).get('live','unknown'))" \
        2>/dev/null || echo "unreachable")
    log "MISP health check: $status"
}

# ── Main ───────────────────────────────────────────────────────────────────────
check_prerequisites
generate_credentials

if [ "$IMPORT_ONLY" = "--import-only" ]; then
    import_offline_feeds
else
    setup_local_misp
    import_offline_feeds
fi

check_misp_health
log "Local MISP threat intelligence platform ready at http://${MISP_BIND_ADDR}:${MISP_PORT}"
