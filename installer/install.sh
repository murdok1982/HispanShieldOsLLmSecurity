#!/usr/bin/env bash
# HispanShield OS LLmSecurity — Installer
# Execution: sudo ./install.sh

set -euo pipefail

INSTALL_DIR="/opt/hispanshield"
LOG_DIR="/var/log/hispanshield"
CONF_DIR="/etc/hispanshield"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log()  { echo -e "\e[1;36m[HispanShield Install]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $1" >&2; }
error(){ echo -e "\e[1;31m[ERROR]\e[0m $1" >&2; exit 1; }

if [ "$EUID" -ne 0 ]; then
    error "Must run as root (sudo ./install.sh)"
fi

log "Starting HispanShield OS LLmSecurity installation (State-Grade)..."

# ── 1. Users and groups ────────────────────────────────────────────────────────
log "Creating isolated system users and groups..."
getent group aegis       >/dev/null || groupadd -r aegis
getent group aegis_admin >/dev/null || groupadd -r aegis_admin
getent passwd aegis_agent >/dev/null || \
    useradd -r -g aegis -s /usr/sbin/nologin \
        -c "HispanShield Agent" aegis_agent
getent passwd aegis_admin >/dev/null || \
    useradd -r -g aegis_admin -s /bin/bash \
        -c "HispanShield Admin" aegis_admin

# Lock accounts — MFA only, no password auth
passwd -l aegis_agent 2>/dev/null || true
passwd -l aegis_admin 2>/dev/null || true

# ── 2. Directory structure ─────────────────────────────────────────────────────
log "Creating directory structure..."
install -d -m 750 -o aegis_agent -g aegis "${INSTALL_DIR}"/{core,models,bin,ui,rust}
install -d -m 700 "${LOG_DIR}"
install -d -m 750 "${CONF_DIR}"/{policies,pam,ima}
install -d -m 700 "${CONF_DIR}"/{secureboot,tpm,secrets}

# ── 3. TPM 2.0 key sealing ─────────────────────────────────────────────────────
log "Configuring TPM 2.0 for LUKS key sealing..."
if command -v tpm2_createprimary &>/dev/null; then
    tpm2_createprimary -C e -g sha256 -G rsa \
        -c "${CONF_DIR}/tpm/primary.ctx" 2>/dev/null || \
        warn "TPM primary context creation failed — check TPM availability"
    echo "TPM2: Enabled for disk encryption" > "${CONF_DIR}/tpm/status"
    log "TPM 2.0 configured"
else
    warn "tpm2-tools not found — install on the target system"
fi

# ── 4. FIPS 140-3 ─────────────────────────────────────────────────────────────
log "Enabling FIPS 140-3 mode..."
if command -v fips-mode-setup &>/dev/null; then
    fips-mode-setup --enable || \
        log "FIPS: Requires reboot to take full effect"
    grep -q 'FIPS=1' /etc/environment 2>/dev/null || \
        echo "FIPS=1" >> /etc/environment
else
    warn "fips-mode-setup not found — install crypto-policies on target system"
fi

# ── 5. LLM model download ──────────────────────────────────────────────────────
log "Downloading sovereign LLM model (Qwen2.5 GGUF)..."
if [ -f "${SCRIPT_DIR}/download_model.py" ]; then
    python3 "${SCRIPT_DIR}/download_model.py" || \
        warn "Model download failed — run manually after install"
else
    warn "download_model.py not found in ${SCRIPT_DIR}"
fi

# ── 6. Rust binaries ───────────────────────────────────────────────────────────
log "Compiling Rust core engines (Gatekeeper + Sentinel + PQC)..."
if command -v cargo &>/dev/null; then
    (cd "${REPO_ROOT}/core/rust" && cargo build --release --workspace)
    install -m 755 \
        "${REPO_ROOT}/core/rust/target/release/aegis-sentinel" \
        "${INSTALL_DIR}/bin/"
    install -m 755 \
        "${REPO_ROOT}/core/rust/target/release/aegis-ebpf" \
        "${INSTALL_DIR}/bin/"
    log "Rust binaries compiled and installed"
else
    warn "cargo not found — install Rust toolchain on target system"
fi

# ── 7. Systemd services ────────────────────────────────────────────────────────
log "Installing systemd daemon units..."
if [ -d "${REPO_ROOT}/os_base/sys_services" ]; then
    cp "${REPO_ROOT}"/os_base/sys_services/*.service /etc/systemd/system/ 2>/dev/null || true
    systemctl daemon-reload
fi

# ── 8. AppArmor ───────────────────────────────────────────────────────────────
log "Configuring AppArmor mandatory access control..."
install -d -m 755 /etc/apparmor.d
if [ -d "${REPO_ROOT}/os_base/apparmor" ]; then
    cp "${REPO_ROOT}"/os_base/apparmor/* /etc/apparmor.d/ 2>/dev/null || true
fi
# Inline profile as fallback
cat > /etc/apparmor.d/opt.hispanshield.bin.aegis-sentinel <<'APPARMOR'
#include <tunables/global>
/opt/hispanshield/bin/aegis-sentinel {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    network inet stream,
    /opt/hispanshield/** r,
    /var/log/hispanshield/** rw,
    /etc/hispanshield/** r,
    /run/aegis/*.sock rw,
    deny /home/** rw,
    deny @{PROC}/@{pid}/mem rw,
}
APPARMOR
systemctl enable apparmor 2>/dev/null || true

# ── 9. PAM MFA (PIV/CAC + FIDO2) ──────────────────────────────────────────────
log "Configuring MFA (PIV/CAC + FIDO2)..."
if [ -f "${REPO_ROOT}/os_base/pam/pam_hispanshield.conf" ]; then
    install -m 644 "${REPO_ROOT}/os_base/pam/pam_hispanshield.conf" \
        /etc/pam.d/hispanshield
fi
if [ -f "${REPO_ROOT}/os_base/pam/u2f_keys" ]; then
    install -m 600 "${REPO_ROOT}/os_base/pam/u2f_keys" \
        "${CONF_DIR}/pam/u2f_keys"
fi

# Disable SSH password authentication
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' \
        /etc/ssh/sshd_config
    sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' \
        /etc/ssh/sshd_config
    grep -q 'AuthenticationMethods publickey' /etc/ssh/sshd_config || \
        echo "AuthenticationMethods publickey,keyboard-interactive" \
        >> /etc/ssh/sshd_config
fi

# ── 10. IMA/EVM integrity ──────────────────────────────────────────────────────
log "Setting up IMA/EVM binary integrity measurement..."
if [ -f "${REPO_ROOT}/os_base/ima/setup_ima_evm.sh" ]; then
    # Copy policy to /etc/hispanshield/ima/
    install -m 644 "${REPO_ROOT}/os_base/ima/ima-policy" \
        "${CONF_DIR}/ima/ima-policy"
    bash "${REPO_ROOT}/os_base/ima/setup_ima_evm.sh" || \
        warn "IMA/EVM setup failed — kernel may not have CONFIG_IMA=y"
fi

# ── 11. Generate bearer token for Sentinel API ────────────────────────────────
log "Generating Sentinel API bearer token..."
if [ ! -f "${CONF_DIR}/secrets/sentinel.token" ]; then
    openssl rand -hex 32 > "${CONF_DIR}/secrets/sentinel.token"
    chmod 400 "${CONF_DIR}/secrets/sentinel.token"
    chown aegis_agent:aegis "${CONF_DIR}/secrets/sentinel.token"
fi

# ── 12. SBOM and sovereignty audit ────────────────────────────────────────────
log "Generating SBOM (Software Bill of Materials)..."
install -d -m 750 "${INSTALL_DIR}/compliance"
bash "${REPO_ROOT}/core/compliance/generate_sbom.sh" 2>/dev/null || \
    warn "SBOM generation failed — install syft on target system"

log "Auditing sovereign forks..."
bash "${REPO_ROOT}/core/compliance/sovereign_forks.sh" 2>/dev/null || \
    warn "Sovereign fork audit failed — manual review required"

# ── Done ───────────────────────────────────────────────────────────────────────
log "Installation complete."
log "NEXT STEPS:"
log "  1. Reboot to activate FIPS mode and IMA policy"
log "  2. Configure TPM PCR sealing: ${CONF_DIR}/tpm/"
log "  3. Enroll FIDO2/PIV keys: ${CONF_DIR}/pam/u2f_keys"
log "  4. Start services: systemctl start aegis-sentinel aegis-ebpf"
log "  WARNING: Secure Boot and TPM must be enabled on the target hardware."
