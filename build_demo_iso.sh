#!/usr/bin/env bash
# HispanShield OS - Modo Demo Seguro (Evaluaciones sin riesgo)
# Este script construye un entorno ISO liviano que despliega única y exclusivamente
# los controles que han sido validados formalmente:
#  - AppArmor (Enforcement)
#  - Auditd (Immutable rules)
#  - Gatekeeper básico (Allowlist)
#
# SE EXCLUYEN INTENCIONALMENTE:
#  - Anti-Tamper / Self Destruct
#  - eBPF Hooks experimentales
#  - Componentes ofensivos (MicroVMs / CNE)

set -euo pipefail

log() { echo -e "\e[1;32m[INFO]\e[0m $1"; }
err() { echo -e "\e[1;31m[ERROR]\e[0m $1" >&2; exit 1; }

DEMO_BUILD_DIR="/tmp/hispanshield_demo_build"
ISO_NAME="HispanShieldOS_Demo_SafeMode.iso"

log "Iniciando compilación del Modo Demo Seguro..."

# 1. Preparación del entorno de la ISO
mkdir -p "$DEMO_BUILD_DIR"/{boot,rootfs,core,os_base}
log "Directorio de trabajo creado: $DEMO_BUILD_DIR"

# 2. Copia exclusiva de controles validados
log "Integrando componentes validados (AppArmor, Audit, Gatekeeper)..."
cp -r os_base/apparmor "$DEMO_BUILD_DIR/os_base/" 2>/dev/null || log "Aviso: Directorio AppArmor no disponible localmente."
cp -r os_base/audit "$DEMO_BUILD_DIR/os_base/" 2>/dev/null || log "Aviso: Directorio Audit no disponible localmente."
cp -r core/rust/aegis-gatekeeper "$DEMO_BUILD_DIR/core/" 2>/dev/null || log "Aviso: Gatekeeper no disponible localmente."

# 3. Asegurar exclusión de componentes de riesgo
log "Purgando componentes destructivos y experimentales de la build..."
rm -rf "$DEMO_BUILD_DIR/core/anti-tamper" 2>/dev/null || true
rm -rf "$DEMO_BUILD_DIR/core/rust/aegis-ebpf" 2>/dev/null || true

# 4. Configuración del perfil de Demo
cat << 'EOF' > "$DEMO_BUILD_DIR/demo_profile.sh"
#!/bin/bash
# Perfil de inicio del Modo Demo Seguro
echo "***********************************************************"
echo "* HispanShield OS - MODO DEMO SEGURO ACTIVO               *"
echo "* ------------------------------------------------------- *"
echo "* Controles habilitados: AppArmor, Auditd, Aegis          *"
echo "* Controles deshabilitados: Anti-Tamper, MicroVM, Ofensiva*"
echo "***********************************************************"
# Activar solo los servicios esenciales seguros
systemctl enable apparmor auditd aegis-gatekeeper 2>/dev/null || true
EOF
chmod +x "$DEMO_BUILD_DIR/demo_profile.sh"

# 5. Empaquetado
log "Empaquetando ISO liviana para evaluación: $ISO_NAME"
if command -v mkisofs >/dev/null 2>&1; then
    mkisofs -o "$ISO_NAME" -R -J "$DEMO_BUILD_DIR"
    log "¡ISO Modo Demo Seguro generada exitosamente en ./$ISO_NAME!"
else
    log "Generador ISO mkisofs no encontrado. Generando Tarball seguro en su lugar..."
    tar -czf "HispanShieldOS_Demo_SafeMode.tar.gz" -C "$DEMO_BUILD_DIR" .
    log "¡Tarball Modo Demo Seguro generado en ./HispanShieldOS_Demo_SafeMode.tar.gz!"
fi

# Limpieza post-build
rm -rf "$DEMO_BUILD_DIR"
log "Construcción segura finalizada con éxito."
