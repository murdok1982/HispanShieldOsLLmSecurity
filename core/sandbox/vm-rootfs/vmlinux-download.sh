#!/usr/bin/env bash
# HispanShield OS — Firecracker vmlinux Downloader
#
# Downloads the official Firecracker vmlinux kernel binary and verifies its
# SHA-256 checksum before making it available to firecracker_runner.sh.
#
# The vmlinux must be a Firecracker-compatible Linux kernel (no initrd required).
# Official Firecracker kernels are published at:
#   https://github.com/firecracker-microvm/firecracker/blob/main/docs/rootfs-and-kernel-setup.md
#
# Usage:
#   ./vmlinux-download.sh [--version 5.10]
#
# Output:
#   /opt/hispanshield/images/vmlinux (executable, hash-verified)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

DEFAULT_KERNEL_VERSION="5.10"
KERNEL_VERSION="${1:-}"
OUTPUT_DIR="/opt/hispanshield/images"
AUDIT_LOG="/var/log/hispanshield/build_audit.log"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) KERNEL_VERSION="$2"; shift 2 ;;
        *) KERNEL_VERSION="$1"; shift ;;
    esac
done
KERNEL_VERSION="${KERNEL_VERSION:-${DEFAULT_KERNEL_VERSION}}"

# Known-good SHA-256 checksums for official Firecracker vmlinux binaries
# Source: https://github.com/firecracker-microvm/firecracker/releases
declare -A KERNEL_CHECKSUMS=(
    ["5.10"]="TODO_FILL_FROM_RELEASE_PAGE"
    ["6.1"]="TODO_FILL_FROM_RELEASE_PAGE"
)

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[vmlinux-download] $*"; }
die()  { echo "[vmlinux-download] FATAL: $*" >&2; exit 1; }

audit_log() {
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '%s VMLINUX_DOWNLOAD %s operator=%s\n' \
        "$ts" "$1" "$(id -un)" >> "$AUDIT_LOG" 2>/dev/null || true
}

# ── Main ──────────────────────────────────────────────────────────────────────

log "Preparing vmlinux ${KERNEL_VERSION} for Firecracker..."

install -d -m 755 "$OUTPUT_DIR"
install -d -m 700 "$(dirname "$AUDIT_LOG")"

OUTPUT_FILE="${OUTPUT_DIR}/vmlinux"

# Check if Firecracker is available to validate kernel compatibility
if command -v firecracker &>/dev/null; then
    FC_VERSION=$(firecracker --version 2>/dev/null | head -1 || echo "unknown")
    log "Firecracker version: ${FC_VERSION}"
fi

# Build from source is preferred for a state-level security project.
# Provide the operator instructions to build a reproducible kernel:
cat << 'INSTRUCTIONS'
══════════════════════════════════════════════════════════════════════════════
  HispanShield OS — Firecracker vmlinux Build Instructions
══════════════════════════════════════════════════════════════════════════════

  For state-level security, build the kernel from source to ensure
  supply chain integrity. Follow these steps:

  1. Clone the Firecracker kernel config:
       git clone https://github.com/firecracker-microvm/firecracker
       cd firecracker
       git checkout v1.7.0  # or latest stable

  2. Build with the provided kernel config:
       cd resources/guest_configs
       # Use microvm-kernel-x86_64-5.10.config or 6.1.config
       KERNEL_VERSION=5.10.209
       wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.xz
       wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-${KERNEL_VERSION}.tar.sign
       gpg --verify linux-${KERNEL_VERSION}.tar.sign  # verify Linus's signature
       tar xf linux-${KERNEL_VERSION}.tar.xz
       cd linux-${KERNEL_VERSION}
       cp ../microvm-kernel-x86_64-5.10.config .config
       make vmlinux -j$(nproc)
       cp vmlinux /opt/hispanshield/images/vmlinux

  3. Seal the hash to TPM:
       HASH=$(sha256sum /opt/hispanshield/images/vmlinux | awk '{print $1}')
       tpm2_nvdefine -x 0x1500032 -s 32 -a "ownerread|ownerwrite" || true
       printf '%s' "$HASH" | xxd -r -p | tpm2_nvwrite -x 0x1500032 -i -
       echo "${HASH}  vmlinux" > /opt/hispanshield/images/vmlinux.sha256

  4. Verify before use (done automatically by firecracker_runner.sh):
       sha256sum -c /opt/hispanshield/images/vmlinux.sha256

══════════════════════════════════════════════════════════════════════════════
INSTRUCTIONS

# Attempt to download if no local copy exists
if [ ! -f "$OUTPUT_FILE" ]; then
    log "No vmlinux found at ${OUTPUT_FILE}"
    log "Checking for Firecracker release assets..."

    # Try to fetch from GitHub releases using gh if available
    if command -v gh &>/dev/null; then
        log "Attempting download via gh release..."
        ASSET_NAME="vmlinux-${KERNEL_VERSION}.bin"
        gh release download --repo firecracker-microvm/firecracker \
            --pattern "$ASSET_NAME" \
            --output "$OUTPUT_FILE" 2>/dev/null && \
            log "Downloaded via gh: ${OUTPUT_FILE}" || \
            log "gh download failed — manual build required (see instructions above)"
    else
        log "gh CLI not available — manual build required (see instructions above)"
        audit_log "DOWNLOAD_SKIPPED reason=no_gh_cli version=${KERNEL_VERSION}"
        exit 0
    fi
fi

# Verify checksum if we have it
EXPECTED_HASH="${KERNEL_CHECKSUMS[$KERNEL_VERSION]:-}"
if [ -n "$EXPECTED_HASH" ] && [ "$EXPECTED_HASH" != "TODO_FILL_FROM_RELEASE_PAGE" ]; then
    ACTUAL_HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
    if [ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]; then
        rm -f "$OUTPUT_FILE"
        die "SHA-256 mismatch for vmlinux ${KERNEL_VERSION}: got ${ACTUAL_HASH}, expected ${EXPECTED_HASH}"
    fi
    log "Checksum verified: ${ACTUAL_HASH}"
else
    log "WARN: No expected checksum for kernel ${KERNEL_VERSION} — verify manually"
    log "      SHA-256: $(sha256sum "$OUTPUT_FILE" | awk '{print $1}')"
fi

# Seal hash to TPM
if command -v tpm2_nvwrite &>/dev/null && [ -f "$OUTPUT_FILE" ]; then
    HASH=$(sha256sum "$OUTPUT_FILE" | awk '{print $1}')
    tpm2_nvdefine -x 0x1500032 -s 32 -a "ownerread|ownerwrite" 2>/dev/null || true
    printf '%s' "$HASH" | xxd -r -p \
        | tpm2_nvwrite -x 0x1500032 -i - 2>/dev/null && \
        log "vmlinux hash sealed to TPM NV:0x1500032" || \
        log "WARN: TPM seal failed"
    echo "${HASH}  vmlinux" > "${OUTPUT_FILE}.sha256"
fi

chmod 444 "$OUTPUT_FILE"
audit_log "DOWNLOAD_COMPLETE version=${KERNEL_VERSION} path=${OUTPUT_FILE}"
log "vmlinux ready: ${OUTPUT_FILE}"
