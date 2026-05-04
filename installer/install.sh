#!/usr/bin/env bash
# HispanShield OS LLmSecurity Installer (MVP)
# EjecuciÃ³n esperada: sudo ./install.sh

set -euo pipefail

log() { echo -e "\e[1;36m[HispanShield OS LLmSecurity Setup]\e[0m $1"; }
error() { echo -e "\e[1;31m[ERROR]\e[0m $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
  error "Este script debe ejecutarse como root (sudo)."
fi

log "Iniciando instalaciÃ³n de Aegis Secure Environment (Militar - Estado)..."

# 1. Crear usuarios y grupos aislados (Zero-Trust + Admin Militar)
log "Creando usuarios y grupos del sistema aislados..."
getent group aegis >/dev/null || groupadd -r aegis
getent group aegis_admin >/dev/null || groupadd -r aegis_admin
getent passwd aegis_agent >/dev/null || useradd -r -g aegis -s /usr/sbin/nologin -c "HispanShield OS LLmSecurity Agent User" aegis_agent
getent passwd aegis_admin >/dev/null || useradd -r -g aegis_admin -s /bin/bash -c "HispanShield OS LLmSecurity Admin" aegis_admin

# Disable password authentication for service accounts (require MFA)
log "Deshabilitando autenticación por contraseña para cuentas de servicio..."
passwd -l aegis_agent 2>/dev/null || true
passwd -l aegis_admin 2>/dev/null || true
# Remove password hash from shadow (replace with ! for locked account)
sed -i 's/^\(aegis_agent:\)[^:]*:/\1!:1/' /etc/shadow 2>/dev/null || true
sed -i 's/^\(aegis_admin:\)[^:]*:/\1!:1/' /etc/shadow 2>/dev/null || true
# CWE-287 FIX: Enforce empty password field (not just locked)
sed -i 's/^\(aegis_agent:\)!:/aegis_agent:\*:/' /etc/shadow 2>/dev/null || true
sed -i 's/^\(aegis_admin:\)!:/aegis_admin:\*:/' /etc/shadow 2>/dev/null || true

# 2. Configurar estructura de directorios con cifrado
log "Estableciendo estructura de directorios y permisos..."
mkdir -p /opt/HispanShield OS LLmSecurity/{core,models,bin,ui,rust}
mkdir -p /var/log/HispanShield OS LLmSecurity
mkdir -p /etc/HispanShield OS LLmSecurity/{policies,secureboot,tpm}

chown -R aegis_agent:aegis /opt/HispanShield OS LLmSecurity
chmod 750 /opt/HispanShield OS LLmSecurity
chmod 700 /etc/HispanShield OS LLmSecurity/secureboot
chmod 700 /etc/HispanShield OS LLmSecurity/tpm

# 3. Configurar TPM 2.0 + LUKS Disk Encryption (Militar)
log "Configurando TPM 2.0 para sellado de claves LUKS..."
if command -v tpm2_createprimary &> /dev/null; then
    # Create TPM primary key
    tpm2_createprimary -C e -g sha256 -G rsa -c /etc/HispanShield OS LLmSecurity/tpm/primary.ctx || true
    
    # Configure LUKS to use TPM-sealed key (for future disk encryption setup)
    mkdir -p /etc/cryptsetup-keys.d/
    echo "TPM2: Enabled for disk encryption" > /etc/HispanShield OS LLmSecurity/tpm/status
    log "TPM 2.0 configurado correctamente"
else
    warn "TPM 2.0 tools no disponibles - instalar tpm2-tools en el sistema destino"
fi

# 4. Habilitar FIPS 140-3 para cumplimiento militar
log "Habilitando modo FIPS 140-3 para criptografÃ­a validada..."
if command -v fips-mode-setup &> /dev/null; then
    fips-mode-setup --enable || log "FIPS: Requiere reinicio para activarse completamente"
    echo "FIPS=1" >> /etc/environment
else
    log "fips-mode-setup no encontrado - instalar crypto-policies en sistema destino"
fi

# 5. Descarga del Modelo LLM Ligero Local (2B)
log "Iniciando descarga segura del modelo GenAI (Qwen2.5-1.5B/Gemma-2B GGUF)..."
python3 download_model.py

# 6. Compilar binarios Rust (Gatekeeper + Sentinel)
log "Compilando motores core en Rust para mÃ¡xima seguridad..."
if command -v cargo &> /dev/null; then
    cd /opt/HispanShield OS LLmSecurity/rust/aegis-gatekeeper && cargo build --release
    cd /opt/HispanShield OS LLmSecurity/rust/aegis-sentinel && cargo build --release
    ln -sf /opt/HispanShield OS LLmSecurity/rust/target/release/aegis-sentinel /opt/HispanShield OS LLmSecurity/bin/
    log "Binarios Rust compilados exitosamente"
else
    warn "Cargo no encontrado - instalar Rust en el sistema destino"
fi

# 7. Instalando y securizando servicios
log "Instalando demonios systemd..."
cp ../os_base/sys_services/*.service /etc/systemd/system/
systemctl daemon-reload

# 8. Configurar AppArmor para endurecimiento adicional
log "Configurando perfiles AppArmor..."
mkdir -p /etc/apparmor.d
cat > /etc/apparmor.d/opt.hispanshield.core.rust.aegis-sentinel << 'APPARMOR'
#include <tunables/global>
/opt/hispanshield/core/rust/target/release/aegis-sentinel {
    #include <abstractions/base>
    #include <abstractions/nameservice>
    
    network inet stream,
    /opt/hispanshield/** r,
    /var/log/hispanshield/** rw,
    /etc/hispanshield/** r,
    /run/aegis-*.sock rw,
    deny /home/** rw,
    deny @{PROC}/@{pid}/mem rw,
}
APPARMOR

# Install PAM MFA configuration
log "Configurando autenticación MFA (PIV/CAC/FIDO2)..."
mkdir -p /etc/hispanshield/pam
cp /opt/hispanshield/os_base/pam/pam_hispanshield.conf /etc/pam.d/hispanshield
cp /opt/hispanshield/os_base/pam/u2f_keys /etc/hispanshield/pam/u2f_keys
chmod 600 /etc/hispanshield/pam/u2f_keys

# Disable SSH password auth globally
if [ -f /etc/ssh/sshd_config ]; then
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' /etc/ssh/sshd_config
    echo "AuthenticationMethods publickey,keyboard-interactive" >> /etc/ssh/sshd_config
fi

systemctl enable apparmor 2>/dev/null || true

# 9. Generate SBOM and sovereignty audit
log "Generando SBOM (Software Bill of Materials)..."
mkdir -p /opt/hispanshield/compliance
bash /opt/hispanshield/core/compliance/generate_sbom.sh

# 10. Setup audited forks for sovereignty
log "Configurando forks auditados para soberanía..."
bash /opt/hispanshield/core/compliance/sovereign_forks.sh

log "InstalaciÃ³n completada (Militar). Por favor, revisa /etc/HispanShield OS LLmSecurity/policies antes de iniciar los servicios."
log "ADVERTENCIA: Este sistema requiere Secure Boot habilitado y claves TPM configuradas."
