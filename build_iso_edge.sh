#!/usr/bin/env bash
# HispanShield OS LLmSecurity - Edge Tactical ISO Builder
# Optimized for low-resource tactical devices (4GB RAM, offline operation)

set -euo pipefail

ISO_NAME="HispanShieldOS-Edge-Tactical.iso"
WORK_DIR="/tmp/hispanshield-edge-build"
CHROOT_DIR="$WORK_DIR/chroot"
IMAGE_DIR="$WORK_DIR/image"

echo "==============================================================="
echo "Iniciando empaquetado Edge Tactical ISO (Militar)..."
echo "==============================================================="

# 1. Prepare minimal dependencies
apt-get update && apt-get install -y debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin mtools \
    openssl sbsigntool tpm2-tools cryptsetup-bin jq

# 2. Clean previous builds
rm -rf "$WORK_DIR"
mkdir -p "$CHROOT_DIR" "$IMAGE_DIR/live" "$IMAGE_DIR/boot/grub"

# 3. Build minimal Debian base (no GUI, minimal packages)
echo "[+] Building minimal Debian base for Edge devices..."
debootstrap --arch=amd64 --variant=minbase stable "$CHROOT_DIR" http://deb.debian.org/debian/

# 4. Inject HispanShield Edge modules
echo "[+] Injecting Edge modules..."
mkdir -p "$CHROOT_DIR/opt/hispanshield"
cp -r ../core ../installer ../os_base ../ui "$CHROOT_DIR/opt/hispanshield/"

# 5. Configure Chroot for Edge environment
cat << 'EOF' > "$CHROOT_DIR/setup-edge.sh"
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devpts none /dev/pts

# Minimal packages for Edge (no GUI, headless)
apt-get update
apt-get install -y --no-install-recommends \
    linux-image-amd64 systemd openssl tpm2-tools cryptsetup-bin \
    curl wget jq iptables nftables auditd apparmor \
    python3-minimal ca-certificates

# Remove unnecessary packages for Edge
apt-get remove --purge -y libx11-* libgtk-* libwebkit* 2>/dev/null || true
apt-get autoremove --purge -y
apt-get clean

# Configure offline update module
mkdir -p /opt/hispanshield/edge/updates
cat > /opt/hispanshield/edge/sneakernet-update.sh << 'UPDATE'
#!/bin/bash
# Sneakernet Offline Update Module (Military)
# Verifies and applies updates from signed USB drives

UPDATE_MOUNT="/media/updates"
SIGNATURE_KEY="/etc/hispanshield/secureboot/keys/db/db.crt"

echo "[Edge Update] Checking for signed updates..."

if [ ! -d "$UPDATE_MOUNT" ]; then
    echo "Insert signed USB update drive and mount at $UPDATE_MOUNT"
    exit 1
fi

# Verify GPG signature of update package
if gpgv --keyring "$SIGNATURE_KEY" "$UPDATE_MOUNT/update.sig" "$UPDATE_MOUNT/update.tar.gz"; then
    echo "[Edge Update] Signature VERIFIED"
    tar -xzf "$UPDATE_MOUNT/update.tar.gz" -C /opt/hispanshield/
    systemctl restart aegis-agent-core aegis-llm-runtime
    echo "[Edge Update] Applied successfully"
else
    echo "[Edge Update] FAILED: Invalid signature"
    exit 1
fi
UPDATE
chmod +x /opt/hispanshield/edge/sneakernet-update.sh

# Pre-download 7B quantized model for Edge (smaller footprint)
mkdir -p /opt/hispanshield/models
# 7B model will be downloaded during install or via sneakernet

umount /proc /sys /dev/pts
rm /setup-edge.sh
EOF

chmod +x "$CHROOT_DIR/setup-edge.sh"
chroot "$CHROOT_DIR" /setup-edge.sh

# 6. Compile SquashFS with high compression for smaller ISO
echo "[+] Compressing Edge FileSystem (SquashFS - high compression)..."
mksquashfs "$CHROOT_DIR" "$IMAGE_DIR/live/filesystem.squashfs" -e boot -comp xz -Xbcj x86 -b 1M

# 7. Copy Edge kernel
cp "$CHROOT_DIR/boot/vmlinuz-"* "$IMAGE_DIR/live/vmlinuz"
cp "$CHROOT_DIR/boot/initrd.img-"* "$IMAGE_DIR/live/initrd"

# 8. Edge GRUB configuration (minimal, fast boot)
cat << 'EOF' > "$IMAGE_DIR/boot/grub/grub.cfg"
set timeout=3

menuentry "HispanShield OS - Edge Tactical (4GB RAM)" {
    linux /live/vmlinuz boot=live quiet splash nomodeset mem=3840M
    initrd /live/initrd
}

menuentry "HispanShield OS - Edge Recovery" {
    linux /live/vmlinuz boot=live single nomodeset
    initrd /live/initrd
}
EOF

# 9. Generate Edge ISO
echo "[+] Packaging Edge Tactical ISO..."
xorriso -as mkisofs \
    -r -J -b boot/grub/i386-pc/eltorito.img \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -o "$ISO_NAME" "$IMAGE_DIR"

echo "==============================================================="
echo "COMPLETADO: $ISO_NAME generado para dispositivos tácticos."
echo "Tamaño: $(du -h $ISO_NAME | cut -f1)"
echo "==============================================================="
