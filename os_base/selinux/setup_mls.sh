#!/usr/bin/env bash
# Configure SELinux for Multi-Level Security (MLS) following Bell-La Padula
# For HispanShield OS State Military deployment

set -euo pipefail

log() { echo -e "\e[1;35m[MLS/SELinux]\e[0m $1"; }

# Install SELinux with MLS support
install_selinux_mls() {
    log "Installing SELinux with MLS policy..."
    apt-get update && apt-get install -y \
        selinux-basics \
        selinux-policy-default \
        selinux-policy-mls \
        auditd \
        checkpolicy \
        policycoreutils \
        policycoreutils-python-utils
    
    # Switch to MLS policy
    sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=mls/' /etc/selinux/config
    echo "MLS=enabled" >> /etc/selinux/mls/setrans.conf
    
    log "SELinux MLS policy installed. Reboot required to activate."
}

# Define security levels (Bell-La Padula)
setup_security_levels() {
    log "Setting up security levels (Confidencial/Secreto/AltoSecreto)..."
    
    cat > /etc/selinux/mls/security_levels.conf << 'LEVELS'
# HispanShield OS Security Levels (Bell-La Padula Model)
# No-Read-Up: Cannot read objects above your clearance
# No-Write-Down: Cannot write objects below your clearance

level Confidencial = 100 {
    desc = "Classified information requiring protection"
    users = "aegis_agent, analyst_low"
}

level Secreto = 200 {
    desc = "Sensitive military operations"
    users = "aegis_admin, analyst_med"
}

level AltoSecreto = 300 {
    desc = "Top secret military intelligence"
    users = "aegis_root, analyst_high, commander"
}
LEVELS

    log "Security levels configured"
}

# Label critical system files
label_system_resources() {
    log "Labeling system resources with MLS classifications..."
    
    # Label Aegis core (Secreto)
    semanage fcontext -a -t aegis_exec_t -r s0-s2 "/opt/hispanshield/core(/.*)?"
    semanage fcontext -a -t aegis_data_t -r s0-s2 "/var/log/hispanshield(/.*)?"
    
    # Label models (Alto Secreto if fine-tuned military)
    semanage fcontext -a -t aegis_model_t -r s0-s3 "/opt/hispanshield/models(/.*)?"
    
    # Apply labels
    restorecon -Rv /opt/hispanshield
    restorecon -Rv /var/log/hispanshield
    
    log "System resources labeled"
}

# Configure user clearances
setup_user_clearances() {
    log "Configuring user clearances..."
    
    # aegis_agent: Confidencial
    semanage login -a -s staff_u -r s0 aegis_agent
    
    # aegis_admin: Secreto
    semanage login -a -s staff_u -r s1 aegis_admin
    
    # root: Alto Secreto (full access)
    semanage login -a -s staff_u -r s2 root
    
    log "User clearances configured"
}

# Main
log "Starting MLS (Multi-Level Security) setup for State Military..."
install_selinux_mls
setup_security_levels
label_system_resources
setup_user_clearances

log "MLS configuration complete. Reboot to activate SELinux MLS."
log "Verify with: 'sestatus' and 'id -Z'"
