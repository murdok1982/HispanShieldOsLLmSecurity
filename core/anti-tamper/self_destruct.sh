#!/usr/bin/env bash
# HispanShield OS - Self-Destruct Module (Military Anti-Tamper)
# Wipes TPM keys and sensitive data on tampering detection

set -euo pipefail

log() { echo -e "\e[1;31m[Self-Destruct]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARNING]\e[0m $1"; }

TPM_KEYS="/etc/hispanshield/tpm"
SECURE_BOOT_KEYS="/etc/hispanshield/secureboot"
AEGIS_DATA="/opt/hispanshield /var/log/hispanshield"

# Monitor for tampering indicators
monitor_tampering() {
    log "Starting anti-tamper monitoring..."
    
    # Check for debugging/tracing
    if grep -q "tracing" /proc/1/status 2>/dev/null; then
        warn "Debugging detected on PID 1"
        trigger_self_destruct "DEBUGGING_DETECTED"
    fi
    
    # Check for unknown kernel modules
    local loaded_modules=$(lsmod | wc -l)
    if [ "$loaded_modules" -gt 100 ]; then
        warn "Excessive kernel modules loaded: $loaded_modules"
        trigger_self_destruct "MODULE_INJECTION"
    fi
    
    # Check for unexpected network connections
    local suspicious_ports=$(netstat -tuln | grep -E ":(4444|31337|1337)" | wc -l)
    if [ "$suspicious_ports" -gt 0 ]; then
        warn "Suspicious ports detected"
        trigger_self_destruct "SUSPICIOUS_NETWORK"
    fi
}

# Wipe TPM keys (irreversible without backup)
wipe_tpm_keys() {
    log "WIPING TPM KEYS - Anti-Tamper activated"
    
    # Clear TPM NV indices (if accessible)
    if command -v tpm2_nvundefine &> /dev/null; then
        tpm2_nvundefine -x 0x1500000 2>/dev/null || true
        tpm2_nvundefine -x 0x1500001 2>/dev/null || true
    fi
    
    # Wipe key files
    shred -vfz "$TPM_KEYS"/* 2>/dev/null || true
    rm -rf "$TPM_KEYS"/*
    
    log "TPM keys WIPED"
}

# Wipe sensitive data
wipe_sensitive_data() {
    log "Wiping sensitive data..."
    
    # Wipe Aegis data
    find /opt/hispanshield -type f -exec shred -vfz {} \; 2>/dev/null || true
    rm -rf /opt/hispanshield/models/* 2>/dev/null || true
    rm -rf /var/log/hispanshield/* 2>/dev/null || true
    
    # Wipe Secure Boot keys
    find /etc/hispanshield/secureboot -type f -exec shred -vfz {} \; 2>/dev/null || true
    
    log "Sensitive data WIPED"
}

# Overwrite LUKS header (make disk unreadable)
wipe_disk_encryption() {
    log "Overwriting LUKS header (disk will be unrecoverable)..."
    
    # Find LUKS-encrypted partitions
    local luks_parts=$(blkid | grep "TYPE=\"crypto_LUKS\"" | cut -d: -f1)
    
    for part in $luks_parts; do
        warn "Wiping LUKS header on $part"
        dd if=/dev/urandom of=$part bs=1M count=10 2>/dev/null || true
    done
    
    log "LUKS headers WIPED - disk now unrecoverable"
}

# Main self-destruct trigger
trigger_self_destruct() {
    local reason="$1"
    error "SELF-DESTRUCT TRIGGERED: $reason"
    
    # Log to immutable audit (if still possible)
    echo "$(date -Iseconds) SELF_DESTRUCT: $reason" >> /var/log/hispanshield/audit.log 2>/dev/null || true
    
    # Kill all Aegis processes
    pkill -9 -f aegis 2>/dev/null || true
    
    # Wipe keys and data
    wipe_tpm_keys
    wipe_sensitive_data
    
    # Wipe disk encryption (makes system unrecoverable)
    wipe_disk_encryption
    
    # Final log
    log "SELF-DESTRUCT COMPLETE - System is now unrecoverable"
    
    # Halt system
    halt -f 2>/dev/null || poweroff -f 2>/dev/null || true
}

# Main monitoring loop
log "Self-Destruct module active (Military Anti-Tamper)"
while true; do
    monitor_tampering
    sleep 60
done
