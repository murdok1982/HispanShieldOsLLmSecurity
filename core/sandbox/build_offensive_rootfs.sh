#!/usr/bin/env bash
# HispanShield OS — Offensive Tools ext4 RootFS Builder
#
# Builds a minimal Debian-based ext4 image containing authorized red-team tools.
# The resulting offensive-tools.ext4 is used by firecracker_runner.sh as a
# read-only overlay inside ephemeral MicroVMs. The image is never executed on
# the host directly; all execution occurs inside the isolated Firecracker VM.
#
# AUTHORIZATION REQUIRED:
#   - Must run as root with HISPANSHIELD_BUILD_TOKEN set
#   - Operator is responsible for keeping the image updated and GPG-signed
#
# Tools installed (all from official Debian repos or verifiable sources):
#   nmap, masscan, nikto, gobuster, sqlmap, hydra, john, hashcat,
#   metasploit-framework (community), responder, impacket, crackmapexec,
#   socat, netcat-traditional, tcpdump, tshark, strace
#
# Output: /opt/hispanshield/images/offensive-tools.ext4 (read-only, GPG-signed)
#
# Usage:
#   sudo HISPANSHIELD_BUILD_TOKEN=<token> ./build_offensive_rootfs.sh [--size-mb 4096]

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SIZE_MB="${OFFENSIVE_ROOTFS_SIZE_MB:-4096}"
OUTPUT_IMAGE="/opt/hispanshield/images/offensive-tools.ext4"
BUILD_DIR="/tmp/hispanshield-offensive-rootfs-$$"
CHROOT_DIR="${BUILD_DIR}/chroot"
AUDIT_LOG="/var/log/hispanshield/build_audit.log"
GPG_KEY_ID="${HISPANSHIELD_GPG_BUILD_KEY:-}"
ARCH="amd64"
SUITE="bookworm"
MIRROR="http://deb.debian.org/debian"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --size-mb) SIZE_MB="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "[OffensiveRootFS] $*"; }
warn() { echo "[OffensiveRootFS] WARN: $*" >&2; }
die()  { echo "[OffensiveRootFS] FATAL: $*" >&2; exit 1; }

audit_log() {
    local ts="$( date -u +%Y-%m-%dT%H:%M:%SZ )"
    printf '%s OFFENSIVE_ROOTFS_BUILD %s operator=%s\n' \
        "$ts" "$1" "$(id -un)" >> "$AUDIT_LOG" 2>/dev/null || true
}

cleanup() {
    log "Cleaning up build directory..."
    if mountpoint -q "${CHROOT_DIR}/proc" 2>/dev/null; then
        umount -lf "${CHROOT_DIR}/proc" 2>/dev/null || true
    fi
    if mountpoint -q "${CHROOT_DIR}/sys" 2>/dev/null; then
        umount -lf "${CHROOT_DIR}/sys" 2>/dev/null || true
    fi
    if mountpoint -q "${CHROOT_DIR}/dev/pts" 2>/dev/null; then
        umount -lf "${CHROOT_DIR}/dev/pts" 2>/dev/null || true
    fi
    if mountpoint -q "${CHROOT_DIR}/dev" 2>/dev/null; then
        umount -lf "${CHROOT_DIR}/dev" 2>/dev/null || true
    fi
    rm -rf "${BUILD_DIR}" 2>/dev/null || true
}
trap cleanup EXIT

# ── Authorization ─────────────────────────────────────────────────────────────

[ "$(id -u)" -eq 0 ] || die "Must run as root"

BUILD_TOKEN="${HISPANSHIELD_BUILD_TOKEN:-}"
[ -n "$BUILD_TOKEN" ] || die "HISPANSHIELD_BUILD_TOKEN not set"

# Verify token against TPM if available
if command -v tpm2_nvread &>/dev/null; then
    stored=$(tpm2_nvread -x 0x1500030 2>/dev/null | xxd -p -c 32 || true)
    if [ -n "$stored" ]; then
        provided_hash=$(printf '%s' "$BUILD_TOKEN" | sha256sum | awk '{print $1}')
        [ "$provided_hash" = "$stored" ] || die "Build token mismatch with TPM NV:0x1500030"
    else
        warn "No build token in TPM NV:0x1500030 — skipping TPM check"
    fi
fi

audit_log "BUILD_START size_mb=${SIZE_MB}"

# ── Prerequisites ─────────────────────────────────────────────────────────────

for cmd in debootstrap mkfs.ext4 chroot; do
    command -v "$cmd" &>/dev/null || die "$cmd not installed"
done

install -d -m 755 "$(dirname "$OUTPUT_IMAGE")"
install -d -m 700 "$(dirname "$AUDIT_LOG")"

# ── Stage 1: Create ext4 image ────────────────────────────────────────────────

log "Creating ${SIZE_MB}MB ext4 image at ${OUTPUT_IMAGE}.tmp..."
dd if=/dev/zero of="${OUTPUT_IMAGE}.tmp" bs=1M count="$SIZE_MB" status=progress
mkfs.ext4 -L "offensive-tools" -F "${OUTPUT_IMAGE}.tmp"

# ── Stage 2: Mount and debootstrap ────────────────────────────────────────────

mkdir -p "$CHROOT_DIR"
mount -o loop "${OUTPUT_IMAGE}.tmp" "$CHROOT_DIR"

log "Running debootstrap (${SUITE}/${ARCH})..."
debootstrap \
    --arch="$ARCH" \
    --include="ca-certificates,curl,gnupg,apt-transport-https,locales" \
    --exclude="tasksel,tasksel-data" \
    "$SUITE" "$CHROOT_DIR" "$MIRROR"

# Bind mounts for chroot
mount --bind /proc   "${CHROOT_DIR}/proc"
mount --bind /sys    "${CHROOT_DIR}/sys"
mount --bind /dev    "${CHROOT_DIR}/dev"
mount --bind /dev/pts "${CHROOT_DIR}/dev/pts"

# ── Stage 3: Install offensive tools in chroot ────────────────────────────────

log "Installing authorized offensive tools..."

# Kali repository for comprehensive tooling
chroot "$CHROOT_DIR" /bin/bash -c "
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export TERM=xterm

# Add Kali Linux repository (GPG-verified)
curl -fsSL https://archive.kali.org/archive-key.asc \
    | gpg --dearmor -o /usr/share/keyrings/kali-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/kali-archive-keyring.gpg] https://http.kali.org/kali kali-rolling main contrib non-free' \
    > /etc/apt/sources.list.d/kali.list

apt-get update -qq

# Core network tools
apt-get install -y --no-install-recommends \
    nmap masscan netcat-traditional socat tcpdump tshark \
    curl wget dnsutils iputils-ping traceroute iproute2 \
    net-tools iptables

# Web application tools
apt-get install -y --no-install-recommends \
    nikto gobuster dirb sqlmap

# Password and credential tools
apt-get install -y --no-install-recommends \
    hydra john hashcat wordlists

# Post-exploitation / Windows
apt-get install -y --no-install-recommends \
    python3-impacket crackmapexec responder

# Debugging and analysis
apt-get install -y --no-install-recommends \
    strace ltrace gdb binutils

# Metasploit (community edition)
apt-get install -y --no-install-recommends metasploit-framework || \
    echo 'WARN: metasploit-framework not available in configured repos'

# Python tooling
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv

# Cleanup
apt-get clean
rm -rf /var/lib/apt/lists/*
find /var/log -type f -delete
"

# ── Stage 4: Vsock agent for tool execution ───────────────────────────────────

log "Installing vsock-based command dispatcher..."
install -D -m 755 \
    "$(dirname "$0")/vsock-dispatcher.sh" \
    "${CHROOT_DIR}/usr/local/sbin/vsock-dispatcher.sh"

# Systemd unit for vsock listener
cat > "${CHROOT_DIR}/etc/systemd/system/aegis-vsock.service" << 'UNIT'
[Unit]
Description=Aegis Vsock Command Dispatcher
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/vsock-dispatcher.sh
Restart=always
RestartSec=1
User=root

[Install]
WantedBy=multi-user.target
UNIT

chroot "$CHROOT_DIR" systemctl enable aegis-vsock.service 2>/dev/null || true

# ── Stage 5: Harden the image ─────────────────────────────────────────────────

log "Hardening rootfs..."
chroot "$CHROOT_DIR" /bin/bash -c "
# Remove interactive shells from login
sed -i 's|/bin/bash|/sbin/nologin|g' /etc/passwd || true

# Lock root password
passwd -l root 2>/dev/null || true

# Remove SSH keys and cron jobs
find /etc/cron* /var/spool/cron -type f -delete 2>/dev/null || true
rm -rf /etc/ssh/ssh_host_* 2>/dev/null || true
"

# Remove chroot mounts before sealing
umount -lf "${CHROOT_DIR}/dev/pts" || true
umount -lf "${CHROOT_DIR}/dev"     || true
umount -lf "${CHROOT_DIR}/sys"     || true
umount -lf "${CHROOT_DIR}/proc"    || true

# ── Stage 6: Seal and sign ────────────────────────────────────────────────────

umount "$CHROOT_DIR"

# Make read-only
tune2fs -O read-only "${OUTPUT_IMAGE}.tmp" 2>/dev/null || true
mv "${OUTPUT_IMAGE}.tmp" "$OUTPUT_IMAGE"
chmod 440 "$OUTPUT_IMAGE"

# Compute and store SHA-256 hash
IMAGE_HASH=$(sha256sum "$OUTPUT_IMAGE" | awk '{print $1}')
echo "$IMAGE_HASH  $(basename "$OUTPUT_IMAGE")" > "${OUTPUT_IMAGE}.sha256"
log "Image SHA-256: ${IMAGE_HASH}"

# Seal hash to TPM
if command -v tpm2_nvwrite &>/dev/null; then
    tpm2_nvdefine -x 0x1500031 -s 32 -a "ownerread|ownerwrite" 2>/dev/null || true
    printf '%s' "$IMAGE_HASH" | xxd -r -p \
        | tpm2_nvwrite -x 0x1500031 -i - 2>/dev/null && \
        log "Image hash sealed to TPM NV:0x1500031" || \
        warn "TPM seal failed — hash only in ${OUTPUT_IMAGE}.sha256"
fi

# GPG-sign if key available
if [ -n "$GPG_KEY_ID" ]; then
    gpg --batch --yes --detach-sign --armor \
        -u "$GPG_KEY_ID" \
        --output "${OUTPUT_IMAGE}.asc" \
        "$OUTPUT_IMAGE"
    log "Image GPG-signed: ${OUTPUT_IMAGE}.asc"
else
    warn "GPG_BUILD_KEY not set — image not signed (set HISPANSHIELD_GPG_BUILD_KEY)"
fi

audit_log "BUILD_COMPLETE hash=${IMAGE_HASH} size_mb=${SIZE_MB}"
log "Offensive tools image ready: ${OUTPUT_IMAGE}"
log "To use: reference in firecracker_runner.sh as OFFENSIVE_TOOLS_IMAGE"
