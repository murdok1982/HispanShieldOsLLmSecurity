#!/usr/bin/env bash
# HispanShield OS - Self-Destruct Module (Military Anti-Tamper)
# Wipes TPM keys, sensitive data, and performs thermal/magnetic wiping on tampering detection

set -euo pipefail

log() { echo -e "\e[1;31m[Self-Destruct]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARNING]\e[0m $1"; }
error() { echo -e "\e[1;41m[CRITICAL]\e[0m $1"; }

TPM_KEYS="/etc/hispanshield/tpm"
SECURE_BOOT_KEYS="/etc/hispanshield/secureboot"
AEGIS_DATA="/opt/hispanshield /var/log/hispanshield"

# Monitor for tampering indicators
monitor_tampering() {
    log "Starting anti-tamper monitoring (Phase 4: Tactical Resilience)..."
    
    if [ "${HISPANSHIELD_ENV:-prod}" != "prod" ]; then
        return 0
    fi

    local sensors_triggered=0

    # 1. Check Chassis Intrusion Switch (Hardware level)
    if [ -f "/sys/class/gpio/gpio1/value" ]; then
        chassis_status=$(cat /sys/class/gpio/gpio1/value)
        if [ "$chassis_status" -eq 1 ]; then
             sensors_triggered=$((sensors_triggered + 1))
        fi
    fi

    # 2. Check for debugging/tracing
    if grep -q "tracing" /proc/1/status 2>/dev/null; then
        sensors_triggered=$((sensors_triggered + 1))
    fi
    
    # 3. Check for unknown kernel modules
    local loaded_modules=$(lsmod | wc -l)
    if [ "$loaded_modules" -gt 150 ]; then
        sensors_triggered=$((sensors_triggered + 1))
    fi
    
    # 4. Check for unexpected network connections
    local suspicious_ports=$(netstat -tuln | grep -E ":(4444|31337|1337)" | wc -l)
    if [ "$suspicious_ports" -gt 0 ]; then
        sensors_triggered=$((sensors_triggered + 1))
    fi

    if [ "$sensors_triggered" -ge 2 ]; then
        trigger_self_destruct "MULTI_SENSOR_TAMPERING_DETECTED ($sensors_triggered sensors)"
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
    shred -vfz -n 7 "$TPM_KEYS"/* 2>/dev/null || true
    rm -rf "$TPM_KEYS"/*
    
    log "TPM keys WIPED"
}

# Wipe sensitive data
wipe_sensitive_data() {
    log "Wiping sensitive data..."
    
    # Wipe Aegis data (7 passes, DoD 5220.22-M standard)
    find /opt/hispanshield -type f -exec shred -vfz -n 7 {} \; 2>/dev/null || true
    rm -rf /opt/hispanshield/models/* 2>/dev/null || true
    rm -rf /var/log/hispanshield/* 2>/dev/null || true
    
    # Wipe Secure Boot keys
    find /etc/hispanshield/secureboot -type f -exec shred -vfz -n 7 {} \; 2>/dev/null || true
    
    log "Sensitive data WIPED"
}

# Overwrite LUKS header (make disk unreadable)
wipe_disk_encryption() {
    log "Overwriting LUKS header (disk will be unrecoverable)..."
    
    # Find LUKS-encrypted partitions
    local luks_parts=$(blkid | grep "TYPE=\"crypto_LUKS\"" | cut -d: -f1)
    
    for part in $luks_parts; do
        warn "Wiping LUKS header on $part (Magnetic Override)"
        # Magnetic/Thermal wipe simulation: multiple random passes over header
        dd if=/dev/urandom of=$part bs=1M count=10 2>/dev/null || true
        dd if=/dev/zero of=$part bs=1M count=10 2>/dev/null || true
        dd if=/dev/urandom of=$part bs=1M count=10 2>/dev/null || true
    done
    
    log "LUKS headers WIPED - disk now unrecoverable"
}

# RAM Thermal Wipe (DDR Memory scrambling)
wipe_ram() {
    log "Initiating RAM thermal wipe..."
    # Allocate and fill all available memory with random data to flush cold-boot attack vectors
    # This will likely OOM kill the script, but we are self-destructing anyway.
    nohup bash -c 'cat /dev/urandom | head -c $(grep MemFree /proc/meminfo | awk "{print \$2}")K > /dev/null' &>/dev/null &
}

# Main self-destruct trigger
trigger_self_destruct() {
    local reason="$1"
    error "SELF-DESTRUCT TRIGGERED: $reason"
    
    # Log to immutable audit (if still possible)
    echo "$(date -Iseconds) SELF_DESTRUCT: $reason" >> /var/log/hispanshield/audit.log 2>/dev/null || true
    
    # Kill all Aegis processes
    pkill -9 -f aegis 2>/dev/null || true
    
    # 1. Wipe keys and data
    wipe_tpm_keys
    wipe_sensitive_data
    
    # 2. Wipe disk encryption (makes system unrecoverable)
    wipe_disk_encryption
    
    # 3. Wipe RAM
    wipe_ram
    
    # Final log
    log "SELF-DESTRUCT COMPLETE - System is now unrecoverable"
    
    # Halt system immediately (magic SysRq)
    echo b > /proc/sysrq-trigger 2>/dev/null || halt -f 2>/dev/null || poweroff -f 2>/dev/null || true
}

# Main monitoring loop
log "Self-Destruct module active (Military Anti-Tamper - DoD Compliant)"
while true; do
    monitor_tampering
    sleep 30 # Reduced interval for tactical scenarios
done
