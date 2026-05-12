#!/bin/bash
# Generar artefacto firmado para auditoría externa

ARTIFACT_DIR="/var/log/hispanshield/audit/$(date +%Y%m%d)"
mkdir -p "$ARTIFACT_DIR"

# 1. Recopilar evidencias
auditctl -l > "$ARTIFACT_DIR/audit_rules.txt"
aa-status --profiled > "$ARTIFACT_DIR/apparmor_status.txt"

# 2. Firmar con clave TPM-bound (si disponible)
if command -v tpm2_sign &> /dev/null; then
    tpm2_sign -k ek -m "$ARTIFACT_DIR/manifest.json" -s "$ARTIFACT_DIR/manifest.sig"
fi

# 3. Generar hash de integridad del paquete
sha256sum "$ARTIFACT_DIR"/* > "$ARTIFACT_DIR/CHECKSUMS"
