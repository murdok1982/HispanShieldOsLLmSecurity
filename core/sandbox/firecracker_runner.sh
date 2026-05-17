#!/usr/bin/env bash
# HispanShield OS — Firecracker MicroVM Tool Runner
#
# Executes offensive tools inside an ephemeral Firecracker microVM.
# Each invocation creates a fresh VM from a read-only base rootfs + ephemeral
# overlay, runs the tool, collects output, and destroys all VM state on exit.
# No persistent writable state survives between runs.
#
# Prerequisites:
#   - firecracker binary in PATH
#   - /opt/hispanshield/vm-rootfs/vmlinux     — stripped Linux kernel
#   - /opt/hispanshield/vm-rootfs/offensive-tools.ext4 — read-only rootfs image
#   - ip/iptables tools for TAP interface management
#   - AUTHORIZED_TARGET env var set by the Gatekeeper before calling this script
#
# Usage (called by the Sentinel/Gatekeeper, not directly by operators):
#   AUTHORIZED_TARGET=10.0.0.5 ./firecracker_runner.sh nmap_scan target=10.0.0.5

set -euo pipefail

TOOL="${1:?Usage: firecracker_runner.sh <tool_name> [key=value ...]}"
shift
ARGS=("$@")

VMLINUX="/opt/hispanshield/vm-rootfs/vmlinux"
BASE_ROOTFS="/opt/hispanshield/vm-rootfs/offensive-tools.ext4"
OVERLAY_DIR="/tmp/aegis-vm-overlays"
AUDIT_LOG="${HISPANSHIELD_AUDIT_LOG:-/var/log/hispanshield/audit.log}"
AUTHORIZED_TARGET="${AUTHORIZED_TARGET:-}"
VSOCK_GUEST_CID=3
VSOCK_TOOL_PORT=1234
VM_MEM_MIB="${AEGIS_VM_MEM_MIB:-1024}"
VM_VCPU="${AEGIS_VM_VCPU:-2}"

VM_ID="aegis-$(date +%s%N | sha256sum | head -c 12)"
ROOTFS_OVERLAY="${OVERLAY_DIR}/${VM_ID}.ext4"
FC_API_SOCK="/tmp/fc-api-${VM_ID}.sock"
FC_CFG="/tmp/fc-cfg-${VM_ID}.json"
TAP_IFACE="tap-${VM_ID:0-8}"  # TAP name max 15 chars
TAP_HOST_IP="172.31.255.1"
TAP_GUEST_IP="172.31.255.2"
FC_PID=""

# ── Audit ──────────────────────────────────────────────────────────────────────
audit_log() {
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s FIRECRACKER_RUNNER %s\n' "$ts" "$1" >> "$AUDIT_LOG" 2>/dev/null || true
}

die() {
    audit_log "ERROR vm_id=${VM_ID} msg=$1"
    echo "[firecracker_runner] FATAL: $1" >&2
    exit 1
}

# ── Prerequisites ──────────────────────────────────────────────────────────────
check_prerequisites() {
    command -v firecracker &>/dev/null || die "firecracker not found in PATH"
    command -v ip          &>/dev/null || die "ip (iproute2) not found"
    command -v iptables    &>/dev/null || die "iptables not found"
    [ -f "$VMLINUX" ]    || die "Kernel image not found: $VMLINUX"
    [ -f "$BASE_ROOTFS" ] || die "Base rootfs not found: $BASE_ROOTFS"
    [ "$(id -u)" -eq 0 ]  || die "Must run as root"
    [ -n "$AUTHORIZED_TARGET" ] || die "AUTHORIZED_TARGET not set — call from Gatekeeper only"
}

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
    # Kill VM process
    [ -n "$FC_PID" ] && kill "$FC_PID" 2>/dev/null || true

    # Remove TAP interface
    ip link set dev "$TAP_IFACE" down 2>/dev/null || true
    ip tuntap del dev "$TAP_IFACE" mode tap 2>/dev/null || true

    # Remove firewall rules for this VM's TAP
    iptables -D FORWARD -i "$TAP_IFACE" -j DROP 2>/dev/null || true
    iptables -D FORWARD -i "$TAP_IFACE" -d "$AUTHORIZED_TARGET" -j ACCEPT 2>/dev/null || true

    # Remove ephemeral overlay and config files
    rm -f "$ROOTFS_OVERLAY" "$FC_CFG" "$FC_API_SOCK"

    audit_log "CLEANUP_DONE vm_id=${VM_ID} tool=${TOOL}"
}
trap cleanup EXIT

# ── Create ephemeral overlay rootfs ───────────────────────────────────────────
create_overlay() {
    install -d -m 700 "$OVERLAY_DIR"
    dd if=/dev/zero of="$ROOTFS_OVERLAY" bs=1M count=512 status=none
    mkfs.ext4 -q "$ROOTFS_OVERLAY"
}

# ── Configure TAP network interface ───────────────────────────────────────────
setup_network() {
    ip tuntap add dev "$TAP_IFACE" mode tap
    ip addr add "${TAP_HOST_IP}/30" dev "$TAP_IFACE"
    ip link set dev "$TAP_IFACE" up

    # Default-deny: all outbound traffic from this VM's TAP is blocked
    iptables -I FORWARD -i "$TAP_IFACE" -j DROP

    # Permit only traffic to the Gatekeeper-authorized target
    if [ -n "$AUTHORIZED_TARGET" ]; then
        iptables -I FORWARD -i "$TAP_IFACE" -d "$AUTHORIZED_TARGET" -j ACCEPT
    fi
}

# ── Write Firecracker VM configuration ────────────────────────────────────────
write_vm_config() {
    cat > "$FC_CFG" <<FCEOF
{
  "boot-source": {
    "kernel_image_path": "${VMLINUX}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ip=${TAP_GUEST_IP}::${TAP_HOST_IP}:255.255.255.252::eth0:off"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${BASE_ROOTFS}",
      "is_root_device": true,
      "is_read_only": true
    },
    {
      "drive_id": "overlay",
      "path_on_host": "${ROOTFS_OVERLAY}",
      "is_root_device": false,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": ${VM_VCPU},
    "mem_size_mib": ${VM_MEM_MIB},
    "smt": false
  },
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "AA:FC:00:00:00:01",
      "host_dev_name": "${TAP_IFACE}"
    }
  ],
  "vsock": {
    "guest_cid": ${VSOCK_GUEST_CID},
    "uds_path": "${FC_API_SOCK}.vsock"
  }
}
FCEOF
}

# ── Start VM ───────────────────────────────────────────────────────────────────
start_vm() {
    firecracker --api-sock "$FC_API_SOCK" --config-file "$FC_CFG" &
    FC_PID=$!
    # Allow VM to boot (kernel + init)
    sleep 3
    kill -0 "$FC_PID" 2>/dev/null || die "Firecracker process died during boot"
}

# ── Send command and collect output ───────────────────────────────────────────
run_tool_in_vm() {
    local cmd="${TOOL}"
    for arg in "${ARGS[@]}"; do
        cmd="${cmd} ${arg}"
    done

    # Send command to tool dispatcher inside the VM via vsock
    local output
    output=$(printf '%s\n' "$cmd" | \
        socat - "VSOCK-CONNECT:${VSOCK_GUEST_CID}:${VSOCK_TOOL_PORT}" 2>/dev/null \
        || echo "[ERROR] vsock communication failed")

    echo "$output"
    audit_log "TOOL_OUTPUT_RECEIVED vm_id=${VM_ID} tool=${TOOL} lines=$(echo "$output" | wc -l)"
}

# ── Main ───────────────────────────────────────────────────────────────────────
check_prerequisites

audit_log "START vm_id=${VM_ID} tool=${TOOL} target=${AUTHORIZED_TARGET}"

create_overlay
setup_network
write_vm_config
start_vm

OUTPUT=$(run_tool_in_vm)
echo "$OUTPUT"

audit_log "COMPLETE vm_id=${VM_ID} tool=${TOOL}"
# cleanup runs via trap EXIT
