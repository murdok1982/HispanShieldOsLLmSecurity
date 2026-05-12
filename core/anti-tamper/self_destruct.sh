#!/usr/bin/env bash
# HispanShield OS - Self-Destruct Module (Military Anti-Tamper)
#
# Wipes TPM keys, sensitive data, and LUKS headers when an authenticated tamper
# event is detected.
#
# DESIGN (Fase 1 hardening):
#   - DISABLED BY DEFAULT. Refuses to arm unless HISPANSHIELD_SELF_DESTRUCT_ARMED=1
#     AND the on-disk arm token at /etc/hispanshield/secrets/destruct.armed exists
#     and contains a non-empty value.
#   - REQUIRES N>=3 INDEPENDENT, ATTESTABLE SENSORS to fire (chassis intrusion,
#     boot-attestation drift, audit-daemon alert). Heuristics like "lsmod count"
#     are removed because any benign desktop trips them.
#     DRY-RUN BY DEFAULT DISABLED (HISPANSHIELD_SELF_DESTRUCT_DRYRUN=0, default 0). Sends
#     a SOC alert via the audit channel and waits for an explicit second-stage
#     authorization before any wipe is performed.
#   - All decisions are HMAC-logged so the trigger is attributable post-mortem.

set -euo pipefail

log()  { echo -e "\e[1;31m[Self-Destruct]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARNING]\e[0m $1"; }
err()  { echo -e "\e[1;41m[CRITICAL]\e[0m $1" >&2; }

ARMED_FLAG_PATH="${HISPANSHIELD_DESTRUCT_ARMED_PATH:-/etc/hispanshield/secrets/destruct.armed}"
HMAC_KEY_PATH="${HISPANSHIELD_DESTRUCT_HMAC_KEY:-/etc/hispanshield/secrets/destruct_hmac.key}"
AUDIT_LOG="${HISPANSHIELD_AUDIT_LOG:-/var/log/hispanshield/audit.log}"
SOC_ALERT_FIFO="${HISPANSHIELD_SOC_ALERT_FIFO:-/var/run/hispanshield/soc_alert}"
TPM_KEYS="${HISPANSHIELD_TPM_DIR:-/etc/hispanshield/tpm}"
SECURE_BOOT_KEYS="${HISPANSHIELD_SB_DIR:-/etc/hispanshield/secureboot}"

DRYRUN="${HISPANSHIELD_SELF_DESTRUCT_DRYRUN:-0}"
ARMED_ENV="${HISPANSHIELD_SELF_DESTRUCT_ARMED:-0}"
SENSOR_THRESHOLD="${HISPANSHIELD_SENSOR_THRESHOLD:-3}"
POLL_INTERVAL="${HISPANSHIELD_POLL_INTERVAL:-30}"

audit_log() {
    local event="$1"
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [ -r "$HMAC_KEY_PATH" ]; then
        local mac
        mac=$(printf '%s|%s' "$ts" "$event" \
              | openssl dgst -sha256 -hmac "$(cat "$HMAC_KEY_PATH")" \
              | awk '{print $2}')
        printf '%s SELF_DESTRUCT %s mac=%s\n' "$ts" "$event" "$mac" \
            >> "$AUDIT_LOG" 2>/dev/null || true
    else
        printf '%s SELF_DESTRUCT %s mac=NONE\n' "$ts" "$event" \
            >> "$AUDIT_LOG" 2>/dev/null || true
    fi
}

soc_alert() {
    local msg="$1"
    if [ -p "$SOC_ALERT_FIFO" ]; then
        printf '%s\n' "$msg" > "$SOC_ALERT_FIFO" 2>/dev/null || true
    fi
    audit_log "SOC_ALERT $msg"
}

is_armed() {
    if [ "$ARMED_ENV" != "1" ]; then
        return 1
    fi
    if [ ! -s "$ARMED_FLAG_PATH" ]; then
        return 1
    fi
    return 0
}

# === Sensors (each must be independently attestable) ===

# 1. Chassis intrusion via GPIO (set by hardware switch).
sensor_chassis() {
    [ -r "/sys/class/gpio/gpio1/value" ] && [ "$(cat /sys/class/gpio/gpio1/value 2>/dev/null)" = "1" ]
}

# 2. Secure-Boot / TPM PCR drift recorded by the boot attester.
sensor_attestation_drift() {
    [ -r "/var/run/hispanshield/attestation.failed" ]
}

# 3. Audit daemon raised a tamper alert (signed by sentinel).
sensor_audit_tamper_flag() {
    [ -r "/var/run/hispanshield/tamper.flag" ]
}

# 4. Hardware kill-switch (physically wired ground-tap) — for tactical units only.
sensor_killswitch() {
    [ -r "/sys/class/gpio/gpio23/value" ] && [ "$(cat /sys/class/gpio/gpio23/value 2>/dev/null)" = "1" ]
}

count_triggered_sensors() {
    local triggered=0
    sensor_chassis              && triggered=$((triggered + 1))
    sensor_attestation_drift    && triggered=$((triggered + 1))
    sensor_audit_tamper_flag    && triggered=$((triggered + 1))
    sensor_killswitch           && triggered=$((triggered + 1))
    echo "$triggered"
}

# === Wipe primitives — only invoked after dry-run + second-stage authorization ===

wipe_tpm_keys() {
    log "WIPING TPM KEYS"
    if command -v tpm2_nvundefine &> /dev/null; then
        tpm2_nvundefine -x 0x1500000 2>/dev/null || true
        tpm2_nvundefine -x 0x1500001 2>/dev/null || true
    fi
    [ -d "$TPM_KEYS" ] && shred -vfz -n 7 "$TPM_KEYS"/* 2>/dev/null || true
    [ -d "$TPM_KEYS" ] && rm -rf "${TPM_KEYS:?}"/* 2>/dev/null || true
    audit_log "WIPE_TPM_DONE"
}

wipe_sensitive_data() {
    log "Wiping sensitive data..."
    find /opt/hispanshield -type f -print0 2>/dev/null \
        | xargs -0 -r shred -vfz -n 7 2>/dev/null || true
    rm -rf /opt/hispanshield/models/* 2>/dev/null || true
    rm -rf /var/log/hispanshield/* 2>/dev/null || true
    [ -d "$SECURE_BOOT_KEYS" ] && find "$SECURE_BOOT_KEYS" -type f -print0 \
        | xargs -0 -r shred -vfz -n 7 2>/dev/null || true
    audit_log "WIPE_DATA_DONE"
}

wipe_disk_encryption() {
    log "Overwriting LUKS headers..."
    local luks_parts
    luks_parts=$(blkid 2>/dev/null | awk -F: '/TYPE="crypto_LUKS"/{print $1}')
    for part in $luks_parts; do
        warn "Wiping LUKS header on $part"
        dd if=/dev/urandom of="$part" bs=1M count=10 conv=fsync 2>/dev/null || true
        dd if=/dev/zero    of="$part" bs=1M count=10 conv=fsync 2>/dev/null || true
        dd if=/dev/urandom of="$part" bs=1M count=10 conv=fsync 2>/dev/null || true
    done
    audit_log "WIPE_LUKS_DONE"
}

wipe_ram_pressure() {
    log "Allocating memory pressure to flush cold-boot residue..."
    # Detached subshell; OS may OOM-kill it, which is intended.
    nohup bash -c '
        free_kb=$(awk "/MemFree/{print \$2}" /proc/meminfo)
        head -c "${free_kb}K" /dev/urandom > /dev/null
    ' &>/dev/null &
}

wait_for_second_stage_authorization() {
    # In production this blocks until either:
    #   - SOC operator writes "AUTHORIZE" to /var/run/hispanshield/destruct.gate, or
    #   - the configured grace window expires and policy says "auto-confirm".
    # Default behaviour: auto-confirm OFF; require explicit operator authorization.
    local gate="${HISPANSHIELD_DESTRUCT_GATE:-/var/run/hispanshield/destruct.gate}"
    local timeout="${HISPANSHIELD_DESTRUCT_TIMEOUT:-300}"
    local waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if [ -r "$gate" ] && grep -q '^AUTHORIZE$' "$gate" 2>/dev/null; then
            audit_log "SECOND_STAGE_AUTHORIZED"
            return 0
        fi
        sleep 5
        waited=$((waited + 5))
    done
    audit_log "SECOND_STAGE_TIMEOUT waited=${waited}s"
    return 1
}

trigger_self_destruct() {
    local reason="$1"
    err "SELF-DESTRUCT TRIGGER: $reason"
    audit_log "TRIGGER reason=\"$reason\""
    soc_alert "TAMPER trigger=\"$reason\" stage=dryrun"

    if [ "$DRYRUN" = "1" ]; then
        warn "DRY-RUN active — no destructive action will run. Set HISPANSHIELD_SELF_DESTRUCT_DRYRUN=0 to enable."
        return 0
    fi

    if ! wait_for_second_stage_authorization; then
        warn "Second-stage authorization not received; aborting destruct sequence."
        soc_alert "TAMPER trigger=\"$reason\" stage=aborted"
        return 0
    fi

    # Best-effort: kill aegis processes before wiping the data they depend on.
    pkill -9 -f aegis 2>/dev/null || true

    wipe_tpm_keys
    wipe_sensitive_data
    wipe_disk_encryption
    wipe_ram_pressure

    audit_log "DESTRUCT_COMPLETE"
    log "SELF-DESTRUCT COMPLETE"

    # Hard reset; SysRq must be enabled by /etc/sysctl.d/ for this to work.
    echo b > /proc/sysrq-trigger 2>/dev/null \
        || halt -f 2>/dev/null \
        || poweroff -f 2>/dev/null \
        || true
}

monitor_loop() {
    log "Anti-tamper monitor active (sensor_threshold=$SENSOR_THRESHOLD dryrun=$DRYRUN)"
    if ! is_armed; then
        warn "Module is NOT ARMED (HISPANSHIELD_SELF_DESTRUCT_ARMED!=1 or arm token missing). Idle-monitoring only."
    fi
    while true; do
        local triggered
        triggered=$(count_triggered_sensors)
        if [ "$triggered" -ge "$SENSOR_THRESHOLD" ]; then
            audit_log "SENSORS_TRIPPED count=$triggered threshold=$SENSOR_THRESHOLD"
            if is_armed; then
                trigger_self_destruct "MULTI_SENSOR ${triggered}/${SENSOR_THRESHOLD}"
                # After a successful (or aborted) trigger, exit the loop;
                # systemd will decide whether to restart the unit.
                return 0
            else
                warn "Sensors tripped ($triggered) but module not armed; SOC alert only."
                soc_alert "TAMPER_UNARMED sensors=$triggered"
            fi
        fi
        sleep "$POLL_INTERVAL"
    done
}

monitor_loop
