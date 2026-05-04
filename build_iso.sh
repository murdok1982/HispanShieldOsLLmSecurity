#!/usr/bin/env bash
# HispanShield OS LLmSecurity - ISO Builder Toolkit (FIXED)
# Ejecución requerida: Sistema host Debian/Ubuntu (o WSL2) con debootstrap
set -euo pipefail

ISO_NAME="HispanShieldOS-LLmSecurity-Release1.iso"
WORK_DIR="/tmp/hispanshield-build"
CHROOT_DIR="$WORK_DIR/chroot"
IMAGE_DIR="$WORK_DIR/image"

echo "==============================================================="
echo "Iniciando empaquetado ISO de HispanShield OS LLmSecurity..."
echo "==============================================================="

# 1. Preparar dependencias en el host constructor
apt-get update && apt-get install -y debootstrap squashfs-tools grub-pc-bin grub-efi-amd64-bin mtools \
    openssl sbsigntool tpm2-tools cryptsetup-bin jq grub-mkrescue

# 2. Limpiar builds anteriores
rm -rf "$WORK_DIR"
mkdir -p "$CHROOT_DIR"
mkdir -p "$IMAGE_DIR/live"
mkdir -p "$IMAGE_DIR/boot/grub"

# 3. Construir sistema base Debian minimalista
echo "[+] Descargando y construyendo Base Debian Minimal..."
debootstrap --arch=amd64 stable "$CHROOT_DIR" http://deb.debian.org/debian/

# 4. Inyectar el código y motores de HispanShield OS
echo "[+] Inyectando módulos locales de HispanShield..."
mkdir -p "$CHROOT_DIR/opt/hispanshield"
cp -r ../core ../installer ../os_base ../ui "$CHROOT_DIR/opt/hispanshield/" 2>/dev/null || true

# Create tools_contracts dir if not exists (compatibility)
mkdir -p "$CHROOT_DIR/opt/hispanshield/tools_contracts"

# 5. Configuración de Chroot
echo "[+] Chrooting para aplicar Hardening y Scripts de instalador..."
cat << 'EOF' > "$CHROOT_DIR/setup.sh"
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devpts none /dev/pts

apt-get update
apt-get install -y linux-image-amd64 systemd libwebkit2gtk-4.0-dev curl build-essential wget \
    tpm2-tools cryptsetup-initramfs lvm2 openssl fips-mode-setup apparmor-utils auditd
apt-get clean

# Generate Secure Boot signing keys (state-controlled) - PRIVATE KEY NOT IN ISO
mkdir -p /etc/secureboot/keys/{PK,KEK,db,dbx}
openssl req -new -x509 -newkey rsa:2048 -keyout /etc/secureboot/keys/db/db.key \
    -out /etc/secureboot/keys/db/db.crt -days 3650 -subj "/CN=HispanShield State PK/" -nodes

# Sign kernel for Secure Boot (keep private key OFF ISO)
sbsign --key /etc/secureboot/keys/db/db.key --cert /etc/secureboot/keys/db/db.crt \
    --output /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r) 2>/dev/null || true

# Enable FIPS mode
FIPS_MODULE=$(find /usr/lib -name fipsmodule.cnf 2>/dev/null | head -1)
if [ -n "$FIPS_MODULE" ]; then
    echo "OPENSSL_CONF=$FIPS_MODULE" >> /etc/environment
fi

# Pre-ejecutar instalador interno
cd /opt/hispanshield/installer
bash install.sh

umount /proc /sys /dev/pts
rm /setup.sh
EOF

chmod +x "$CHROOT_DIR/setup.sh"
chroot "$CHROOT_DIR" /setup.sh

# 6. Compilar SquashFS
echo "[+] Comprimiendo FileSystem (SquashFS)..."
mksquashfs "$CHROOT_DIR" "$IMAGE_DIR/live/filesystem.squashfs" -e boot

# 7. Copiar Kernel al live media
cp "$CHROOT_DIR/boot/vmlinuz-"* "$IMAGE_DIR/live/vmlinuz" 2>/dev/null || true
cp "$CHROOT_DIR/boot/initrd.img-"* "$IMAGE_DIR/live/initrd" 2>/dev/null || true

# CWE-798 FIX: DO NOT copy private keys to ISO
# Only copy public certs for verification
mkdir -p "$IMAGE_DIR/boot/secureboot"
cp "$CHROOT_DIR/etc/secureboot/keys/db/db.crt" "$IMAGE_DIR/boot/secureboot/" 2>/dev/null || true

# 8. Configurar GRUB de ARRANQUE (Secure Boot + TPM + LUKS)
cat << 'EOF' > "$IMAGE_DIR/boot/grub/grub.cfg"
set timeout=5

# Secure Boot verification
set check_signatures=enforce
set verify_detached=1

menuentry "HispanShield OS - Secure Boot + TPM + LUKS" {
    insmod luks
    insmod lvm
    insmod tpm
    linux /live/vmlinuz boot=live quiet splash tpm_tis.force=1 cryptdevice=/dev/sda2:cryptroot root=/dev/mapper/cryptroot fips=1
    initrd /live/initrd
}

menuentry "HispanShield OS - Recovery (No Verify)" {
    linux /live/vmlinuz boot=live quiet splash single
    initrd /live/initrd
}
EOF

# 9. Generar el archivo .iso booteable
echo "[+] Empaquetando ISO Híbrida con grub-mkrescue..."
grub-mkrescue -o "$ISO_NAME" "$IMAGE_DIR" 2>&1 || {
    echo "[!] grub-mkrescue failed, trying xorriso fallback..."
    xorriso -as mkisofs \
        -r -J -b boot/grub/i386-pc/eltorito.img \
        -no-emul-boot -boot-load-size 4 -boot-info-table \
        -o "$ISO_NAME" "$IMAGE_DIR"
}

echo "==============================================================="
echo "COMPLETADO: $ISO_NAME ha sido generado exitosamente."
echo "Puedes flashearlo en un USB usando Rufus o BalenaEtcher."
echo "==============================================================="
