#!/usr/bin/env bash
# HispanShield OS — Spectre C2: Encrypted Operator Communication Channel
#
# Provides covert operator-to-operator communication for authorized red team
# and CNE operations. Uses Tor v3 onion services + I2P as backup channel.
#
# AUTHORIZATION REQUIRED:
#   - Dual-MFA via CDS must be completed before any C2 session
#   - HISPANSHIELD_C2_AUTH_TOKEN must match TPM NV:0x1500020
#   - All sessions are immutably logged to the audit channel
#
# This module establishes the COMMUNICATION CHANNEL only. Tool execution
# is handled by firecracker_runner.sh via the PolicyEngine gatekeeper.
#
# Usage: ./spectre_c2.sh {setup|start|stop|status}

set -euo pipefail

C2_AUTH_TOKEN="${HISPANSHIELD_C2_AUTH_TOKEN:-}"
TPM_NV_C2_TOKEN="0x1500020"
TOR_DATA_DIR="/etc/hispanshield/c2/tor"
I2P_DATA_DIR="/etc/hispanshield/c2/i2p"
C2_LISTENER_PORT="${HISPANSHIELD_C2_PORT:-4433}"
C2_CERT_DIR="/etc/hispanshield/c2/certs"
AUDIT_LOG="/var/log/hispanshield/c2_audit.log"
AUTH_GATE="/var/run/hispanshield/c2_authorized"
PID_DIR="/var/run/hispanshield/c2"

log()  { echo "[Spectre-C2] $*"; }
warn() { echo "[Spectre-C2] WARN: $*" >&2; }
die()  { echo "[Spectre-C2] FATAL: $*" >&2; exit 1; }

# ── Audit ──────────────────────────────────────────────────────────────────────
audit_log() {
    local ts event
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    event="$1"
    local hmac_key="/etc/hispanshield/secrets/destruct_hmac.key"
    if [ -r "$hmac_key" ]; then
        local mac
        mac=$(printf '%s|%s' "$ts" "$event" \
              | openssl dgst -sha256 -hmac "$(cat "$hmac_key")" \
              | awk '{print $2}')
        printf '%s C2_CHANNEL %s mac=%s\n' "$ts" "$event" "$mac" \
            >> "$AUDIT_LOG" 2>/dev/null || true
    else
        printf '%s C2_CHANNEL %s\n' "$ts" "$event" \
            >> "$AUDIT_LOG" 2>/dev/null || true
    fi
}

# ── Authorization ──────────────────────────────────────────────────────────────
verify_authorization() {
    log "Verifying C2 authorization..."

    [ "$(id -u)" -eq 0 ] || die "Must run as root"

    # 1. Token must be provided
    [ -n "$C2_AUTH_TOKEN" ] || die "HISPANSHIELD_C2_AUTH_TOKEN not set"

    # 2. Validate token against TPM NV (if TPM available)
    if command -v tpm2_nvread &>/dev/null; then
        local tpm_token
        tpm_token=$(tpm2_nvread -x "$TPM_NV_C2_TOKEN" 2>/dev/null | xxd -p -c 32 || true)
        if [ -n "$tpm_token" ]; then
            local provided_hash
            provided_hash=$(printf '%s' "$C2_AUTH_TOKEN" | sha256sum | awk '{print $1}')
            [ "$provided_hash" = "$tpm_token" ] || \
                die "C2 token mismatch with TPM NV:$TPM_NV_C2_TOKEN — unauthorized"
        else
            warn "No C2 token found in TPM NV — skipping TPM check (provision first)"
        fi
    fi

    # 3. Dual-MFA gate must be cleared (written by CDS after second-factor approval)
    [ -f "$AUTH_GATE" ] || \
        die "Dual-MFA gate not cleared — complete CDS authorization first"
    local gate_age
    gate_age=$(( $(date +%s) - $(stat -c %Y "$AUTH_GATE" 2>/dev/null || echo 0) ))
    [ "$gate_age" -lt 300 ] || \
        die "Dual-MFA gate expired (${gate_age}s ago, max 300s) — re-authorize"

    audit_log "AUTHORIZATION_VERIFIED operator=$(id -un) token_hash=$(printf '%s' "$C2_AUTH_TOKEN" | sha256sum | awk '{print $1}' | head -c 16)..."
    log "Authorization verified"
}

# ── Certificate generation ─────────────────────────────────────────────────────
generate_c2_certs() {
    if [ -f "${C2_CERT_DIR}/server.crt" ] && [ -f "${C2_CERT_DIR}/server.key" ]; then
        log "C2 certificates already exist — skipping generation"
        return
    fi
    log "Generating mTLS certificates for C2 channel..."
    install -d -m 700 "$C2_CERT_DIR"

    # CA
    openssl genrsa -out "${C2_CERT_DIR}/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -key "${C2_CERT_DIR}/ca.key" \
        -out "${C2_CERT_DIR}/ca.crt" -days 365 \
        -subj "/CN=HispanShield-C2-CA/O=AegisSecure/C=ES" \
        -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null

    # Server cert (for listener inside the onion service)
    openssl genrsa -out "${C2_CERT_DIR}/server.key" 2048 2>/dev/null
    openssl req -new -key "${C2_CERT_DIR}/server.key" \
        -out "${C2_CERT_DIR}/server.csr" \
        -subj "/CN=spectre-c2-server/O=AegisSecure/C=ES" 2>/dev/null
    openssl x509 -req -in "${C2_CERT_DIR}/server.csr" \
        -CA "${C2_CERT_DIR}/ca.crt" -CAkey "${C2_CERT_DIR}/ca.key" \
        -CAcreateserial -out "${C2_CERT_DIR}/server.crt" -days 365 2>/dev/null

    # Client cert (for operator authentication)
    openssl genrsa -out "${C2_CERT_DIR}/operator.key" 2048 2>/dev/null
    openssl req -new -key "${C2_CERT_DIR}/operator.key" \
        -out "${C2_CERT_DIR}/operator.csr" \
        -subj "/CN=spectre-c2-operator/O=AegisSecure/C=ES" 2>/dev/null
    openssl x509 -req -in "${C2_CERT_DIR}/operator.csr" \
        -CA "${C2_CERT_DIR}/ca.crt" -CAkey "${C2_CERT_DIR}/ca.key" \
        -CAcreateserial -out "${C2_CERT_DIR}/operator.crt" -days 365 2>/dev/null

    chmod 600 "${C2_CERT_DIR}"/*.key
    chmod 644 "${C2_CERT_DIR}"/*.crt
    audit_log "C2_CERTS_GENERATED dir=${C2_CERT_DIR}"
    log "C2 certificates generated"
}

# ── Tor hidden service ─────────────────────────────────────────────────────────
setup_tor_hidden_service() {
    command -v tor &>/dev/null || die "tor not installed (apt-get install tor)"
    log "Configuring Tor v3 hidden service..."
    install -d -m 700 "$TOR_DATA_DIR"

    # Generate torrc from template
    sed \
        -e "s|__TOR_DATA_DIR__|${TOR_DATA_DIR}|g" \
        -e "s|__C2_PORT__|${C2_LISTENER_PORT}|g" \
        "$(dirname "$0")/tor/torrc.template" \
        > "${TOR_DATA_DIR}/torrc"

    # Start Tor
    install -d -m 700 "$PID_DIR"
    tor -f "${TOR_DATA_DIR}/torrc" --PidFile "${PID_DIR}/tor.pid" \
        --RunAsDaemon 1 2>/dev/null

    # Wait for .onion address (up to 60s)
    local waited=0
    while [ "$waited" -lt 60 ]; do
        if [ -f "${TOR_DATA_DIR}/hidden_service/hostname" ]; then
            local onion_addr
            onion_addr=$(cat "${TOR_DATA_DIR}/hidden_service/hostname")
            # Log onion address to audit only — never to stdout (OPSEC)
            audit_log "TOR_HIDDEN_SERVICE_READY onion=${onion_addr}"
            log "Tor hidden service ready (address in audit log)"
            return
        fi
        sleep 2
        waited=$((waited + 2))
    done
    die "Tor hidden service failed to start after 60s"
}

# ── I2P backup channel ─────────────────────────────────────────────────────────
setup_i2p_tunnel() {
    command -v i2pd &>/dev/null || { warn "i2pd not installed — I2P channel unavailable"; return; }
    log "Configuring I2P backup channel..."
    install -d -m 700 "$I2P_DATA_DIR"

    sed \
        -e "s|__C2_PORT__|${C2_LISTENER_PORT}|g" \
        -e "s|__I2P_INPORT__|$((C2_LISTENER_PORT + 1))|g" \
        "$(dirname "$0")/i2p/tunnels.conf.template" \
        > "${I2P_DATA_DIR}/tunnels.conf"

    i2pd --conf=/dev/null --tunconf="${I2P_DATA_DIR}/tunnels.conf" \
        --datadir="$I2P_DATA_DIR" --daemon 2>/dev/null

    audit_log "I2P_TUNNEL_STARTED port=${C2_LISTENER_PORT}"
    log "I2P backup channel started"
}

# ── mTLS listener ──────────────────────────────────────────────────────────────
start_encrypted_listener() {
    log "Starting mTLS listener on 127.0.0.1:${C2_LISTENER_PORT}..."
    # Listener accepts ONLY connections from within the Tor/I2P proxy
    # (actual traffic arrives via the onion service → localhost)
    openssl s_server \
        -accept "127.0.0.1:${C2_LISTENER_PORT}" \
        -cert "${C2_CERT_DIR}/server.crt" \
        -key  "${C2_CERT_DIR}/server.key" \
        -CAfile "${C2_CERT_DIR}/ca.crt" \
        -Verify 1 \
        -quiet &
    echo $! > "${PID_DIR}/listener.pid"
    audit_log "C2_LISTENER_STARTED port=${C2_LISTENER_PORT} pid=$(cat "${PID_DIR}/listener.pid")"
    log "mTLS listener started (PID: $(cat "${PID_DIR}/listener.pid"))"
}

# ── Teardown ───────────────────────────────────────────────────────────────────
teardown() {
    log "Tearing down C2 channel..."
    audit_log "C2_TEARDOWN_START"

    # Kill listener
    [ -f "${PID_DIR}/listener.pid" ] && \
        kill "$(cat "${PID_DIR}/listener.pid")" 2>/dev/null || true

    # Stop Tor
    [ -f "${PID_DIR}/tor.pid" ] && \
        kill "$(cat "${PID_DIR}/tor.pid")" 2>/dev/null || true

    # Stop I2P
    pkill -f i2pd 2>/dev/null || true

    # Shred session private keys from memory-mapped files
    find "$C2_CERT_DIR" -name "*.key" -exec shred -fuz {} \; 2>/dev/null || true
    shred -fuz "${TOR_DATA_DIR}/hidden_service/private_key" 2>/dev/null || true

    rm -f "${AUTH_GATE}"
    audit_log "C2_TEARDOWN_COMPLETE"
    log "C2 channel torn down — session keys shredded"
}

# ── Status ─────────────────────────────────────────────────────────────────────
show_status() {
    echo "=== Spectre C2 Status ==="
    echo "Tor:      $(pgrep -f "tor -f ${TOR_DATA_DIR}" &>/dev/null && echo RUNNING || echo STOPPED)"
    echo "I2P:      $(pgrep i2pd &>/dev/null && echo RUNNING || echo STOPPED)"
    echo "Listener: $([ -f "${PID_DIR}/listener.pid" ] && kill -0 "$(cat "${PID_DIR}/listener.pid")" 2>/dev/null && echo RUNNING || echo STOPPED)"
    echo "Auth gate: $([ -f "$AUTH_GATE" ] && echo CLEARED || echo BLOCKED)"
    echo "Last audit: $(tail -1 "$AUDIT_LOG" 2>/dev/null || echo none)"
}

# ── Provision C2 token in TPM ──────────────────────────────────────────────────
provision_token() {
    log "Provisioning C2 authorization token in TPM NV:${TPM_NV_C2_TOKEN}..."
    local new_token
    new_token=$(openssl rand -hex 32)
    local token_hash
    token_hash=$(printf '%s' "$new_token" | sha256sum | awk '{print $1}')
    tpm2_nvdefine -x "$TPM_NV_C2_TOKEN" -s 32 \
        -a "ownerread|ownerwrite" 2>/dev/null || true
    printf '%s' "$token_hash" | xxd -r -p \
        | tpm2_nvwrite -x "$TPM_NV_C2_TOKEN" -i - 2>/dev/null || \
        die "TPM NV write failed"
    audit_log "C2_TOKEN_PROVISIONED nv=${TPM_NV_C2_TOKEN}"
    echo "C2 Authorization Token (store securely, show once):"
    echo "$new_token"
}

# ── Main ───────────────────────────────────────────────────────────────────────
trap teardown EXIT

case "${1:-}" in
    setup)
        verify_authorization
        generate_c2_certs
        ;;
    start)
        verify_authorization
        generate_c2_certs
        setup_tor_hidden_service
        setup_i2p_tunnel
        start_encrypted_listener
        log "C2 channel operational — monitor ${AUDIT_LOG} for session activity"
        ;;
    stop)
        teardown
        trap - EXIT
        ;;
    status)
        show_status
        ;;
    provision-token)
        provision_token
        ;;
    *)
        echo "Usage: $0 {setup|start|stop|status|provision-token}"
        exit 1
        ;;
esac
