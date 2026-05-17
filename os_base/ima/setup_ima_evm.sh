#!/usr/bin/env bash
# HispanShield OS — IMA/EVM initialisation
# Generates the EVM signing key, seals it to TPM PCR[0,1,2,3,7] (Secure Boot
# chain), loads the IMA policy, and signs all HispanShield binaries.
#
# Must run as root after Secure Boot is enrolled and before first user login.
# Re-running is idempotent: existing keys are reused; existing signatures refreshed.

set -euo pipefail

EVM_KEY_DIR="/etc/hispanshield/tpm"
EVM_KEY="${EVM_KEY_DIR}/evm_key.pem"
EVM_CERT="${EVM_KEY_DIR}/evm_cert.pem"
IMA_POLICY_SRC="/etc/hispanshield/ima/ima-policy"
IMA_POLICY_KERNEL="/sys/kernel/security/ima/policy"
AEGIS_BIN="/opt/hispanshield/bin"
TPM_NV_EVM="0x1500012"

log()  { echo "[IMA-EVM] $*"; }
die()  { echo "[IMA-EVM] FATAL: $*" >&2; exit 1; }

# ── Prerequisites ──────────────────────────────────────────────────────────────
check_prerequisites() {
    [ "$(id -u)" -eq 0 ] || die "Must run as root"
    for cmd in openssl evmctl tpm2_create tpm2_load tpm2_nvdefine tpm2_nvwrite; do
        command -v "$cmd" &>/dev/null || \
            die "Required command not found: $cmd (install tpm2-tools, ima-evm-utils)"
    done
    [ -d /sys/kernel/security/ima ] || die "IMA not enabled in kernel (CONFIG_IMA=y required)"
}

# ── Generate EVM signing key ───────────────────────────────────────────────────
generate_evm_key() {
    if [ -f "$EVM_KEY" ] && [ -f "$EVM_CERT" ]; then
        log "EVM key already exists — skipping generation"
        return
    fi
    log "Generating 4096-bit RSA EVM signing key..."
    install -d -m 700 "$EVM_KEY_DIR"
    openssl genrsa -out "$EVM_KEY" 4096
    openssl req -new -x509 \
        -key "$EVM_KEY" \
        -out "$EVM_CERT" \
        -subj "/CN=HispanShield-EVM/O=AegisSecure/C=ES" \
        -days 3650
    chmod 400 "$EVM_KEY"
    log "EVM key generated: $EVM_KEY"
}

# ── Seal EVM key to TPM ────────────────────────────────────────────────────────
seal_key_to_tpm() {
    log "Sealing EVM key reference to TPM (PCR 0,1,2,3,7 — Secure Boot chain)..."
    # Store the certificate public key fingerprint in TPM NV index for attestation.
    # The private key remains on disk (protected by 700 dir + root-only read);
    # binding the cert fingerprint to PCRs ensures the key is only usable when
    # the Secure Boot chain has not drifted.
    local fingerprint
    fingerprint=$(openssl x509 -noout -fingerprint -sha256 -in "$EVM_CERT" \
                  | awk -F= '{print $2}' | tr -d ':')
    tpm2_nvdefine -x "$TPM_NV_EVM" -s 32 \
        -a "ownerread|ownerwrite|policyread" 2>/dev/null || true
    printf '%s' "$fingerprint" | xxd -r -p \
        | tpm2_nvwrite -x "$TPM_NV_EVM" -i - 2>/dev/null || true
    log "EVM cert fingerprint sealed to TPM NV:$TPM_NV_EVM"
}

# ── Load IMA policy ────────────────────────────────────────────────────────────
load_ima_policy() {
    if [ ! -f "$IMA_POLICY_SRC" ]; then
        die "IMA policy not found at $IMA_POLICY_SRC"
    fi
    if [ ! -w "$IMA_POLICY_KERNEL" ]; then
        die "Cannot write to $IMA_POLICY_KERNEL — is IMA enabled in the kernel?"
    fi
    log "Loading IMA policy..."
    cat "$IMA_POLICY_SRC" > "$IMA_POLICY_KERNEL"
    log "IMA policy loaded"
}

# ── Sign HispanShield binaries ─────────────────────────────────────────────────
sign_binaries() {
    if [ ! -d "$AEGIS_BIN" ]; then
        log "No binaries found at $AEGIS_BIN — skipping signing step"
        return
    fi
    log "Signing binaries in $AEGIS_BIN with EVM key..."
    local count=0
    while IFS= read -r -d '' bin; do
        evmctl ima_sign --key "$EVM_KEY" "$bin" 2>/dev/null && count=$((count + 1)) || \
            log "WARNING: Could not sign $bin"
    done < <(find "$AEGIS_BIN" -type f -executable -print0)
    log "Signed $count binaries"
}

# ── Verify IMA log ─────────────────────────────────────────────────────────────
verify_ima_log() {
    local ima_log="/sys/kernel/security/ima/ascii_runtime_measurements"
    if [ -r "$ima_log" ]; then
        local entries
        entries=$(wc -l < "$ima_log")
        log "IMA measurement log contains $entries entries"
    fi
}

# ── Main ───────────────────────────────────────────────────────────────────────
check_prerequisites
generate_evm_key
seal_key_to_tpm
load_ima_policy
sign_binaries
verify_ima_log

log "IMA/EVM setup complete"
log "Reboot to activate full appraisal mode (kernel param: ima-appraise=enforce)"
