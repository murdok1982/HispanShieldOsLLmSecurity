#!/usr/bin/env bash
# HispanShield OS LLmSecurity - ISO Builder Toolkit
# Ejecución requerida: Sistema host Debian/Ubuntu (o WSL2) con debootstrap, squashfs-tools y xorriso instalados.
# Uso: sudo ./build_iso.sh

set -euo pipefail

ISO_NAME="HispanShieldOS-LLmSecurity-Release1.iso"
WORK_DIR="/tmp/hispanshield-build"
CHROOT_DIR="$WORK_DIR/chroot"
IMAGE_DIR="$WORK_DIR/image"

echo "==============================================================="
echo "Iniciando empaquetado ISO de HispanShield OS LLmSecurity..."
echo "==============================================================="

# 1. Preparar dependencias en el host constructor
apt-get update && apt-get install -y debootstrap squashfs-tools xorriso grub-pc-bin grub-efi-amd64-bin mtools \
    openssl sbsigntool tpm2-tools cryptsetup-bin

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
cp -r ../core ../installer ../os_base ../tools_contracts ../ui "$CHROOT_DIR/opt/hispanshield/"

# 5. Configuración de Chroot (Kernel, drivers e instalación interna)
echo "[+] Chrooting para aplicar Hardening y Scripts de instalador..."
cat << 'EOF' > "$CHROOT_DIR/setup.sh"
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devpts none /dev/pts

apt-get update
# Instalar dependencias puras para Tauri, Rust, LLM y MILITARY SECURITY
apt-get install -y linux-image-amd64 systemd libwebkit2gtk-4.0-dev curl build-essential wget \
    tpm2-tools cryptsetup-initramfs lvm2 openssl fips-mode-setup apparmor-utils auditd
apt-get clean

# Generate Secure Boot signing keys (state-controlled)
mkdir -p /etc/secureboot/keys/{PK,KEK,db,dbx}
openssl req -new -x509 -newkey rsa:2048 -keyout /etc/secureboot/keys/db/db.key \
    -out /etc/secureboot/keys/db/db.crt -days 3650 -subj "/CN=HispanShield State PK/" -nodes
cp /etc/secureboot/keys/db/db.crt /etc/secureboot/keys/db/db.der
openssl x509 -in /etc/secureboot/keys/db/db.crt -outform DER -out /etc/secureboot/keys/db/db.der

# Sign kernel for Secure Boot
sbsign --key /etc/secureboot/keys/db/db.key --cert /etc/secureboot/keys/db/db.crt \
    --output /boot/vmlinuz-$(uname -r) /boot/vmlinuz-$(uname -r)

# Enable FIPS mode for OpenSSL (military crypto compliance)
FIPS_MODULE=$(find /usr/lib -name fipsmodule.cnf 2>/dev/null | head -1)
if [ -n "$FIPS_MODULE" ]; then
    echo "OPENSSL_CONF=$FIPS_MODULE" >> /etc/environment
fi

# Pre-ejecutar instalador interno (usuarios seguros, políticas)
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

# 7. Copiar Kernel al live media (Secure Boot signed)
cp "$CHROOT_DIR/boot/vmlinuz-"* "$IMAGE_DIR/live/vmlinuz"
cp "$CHROOT_DIR/boot/initrd.img-"* "$IMAGE_DIR/live/initrd"
# Copy Secure Boot keys to ISO for verification
mkdir -p "$IMAGE_DIR/boot/secureboot"
cp -r "$CHROOT_DIR/etc/secureboot/keys" "$IMAGE_DIR/boot/secureboot/"

# 8. Configurar GRUB de ARRANQUE (Secure Boot + TPM + LUKS)
cat << 'EOF' > "$IMAGE_DIR/boot/grub/grub.cfg"
set timeout=5

# Secure Boot verification
set check_signatures=enforce
set verify_detached=1

menuentry "HispanShield OS LLmSecurity (Secure Boot + TPM + LUKS)" {
    insmod luks
    insmod lvm
    insmod tpm
    linux /live/vmlinuz boot=live quiet splash tpm_tis.force=1 cryptdevice=/dev/sda2:cryptroot root=/dev/mapper/cryptroot fips=1
    initrd /live/initrd
}

menuentry "HispanShield OS LLmSecurity (Recovery - No Verify)" {
    linux /live/vmlinuz boot=live quiet splash single
    initrd /live/initrd
}
EOF

# 9. Generar el archivo .iso booteable
echo "[+] Empaquetando ISO Híbrida con xorriso..."
xorriso -as mkisofs \
    -r -J -b boot/grub/i386-pc/eltorito.img \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -o "$ISO_NAME" "$IMAGE_DIR"

echo "==============================================================="
echo "COMPLETADO: $ISO_NAME ha sido generado exitosamente."
echo "Puedes flashearlo en un USB usando Rufus o BalenaEtcher."
echo "==============================================================="
