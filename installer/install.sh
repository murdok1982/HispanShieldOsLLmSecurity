#!/usr/bin/env bash
# HispanShield OS LLmSecurity Installer (MVP)
# EjecuciÃ³n esperada: sudo ./install.sh

set -euo pipefail

log() { echo -e "\e[1;36m[HispanShield OS LLmSecurity Setup]\e[0m $1"; }
error() { echo -e "\e[1;31m[ERROR]\e[0m $1"; exit 1; }

if [ "$EUID" -ne 0 ]; then
  error "Este script debe ejecutarse como root (sudo)."
fi

log "Iniciando instalaciÃ³n de Aegis Secure Environment..."

# 1. Crear usuarios y grupos aislados (Zero-Trust)
log "Creando usuarios y grupos del sistema aislados..."
getent group aegis >/dev/null || groupadd -r aegis
getent passwd aegis_agent >/dev/null || useradd -r -g aegis -s /usr/sbin/nologin -c "HispanShield OS LLmSecurity Agent User" aegis_agent

# 2. Configurar estructura de directorios
log "Estableciendo estructura de directorios y permisos..."
mkdir -p /opt/HispanShield OS LLmSecurity/{core,models,bin,ui}
mkdir -p /var/log/HispanShield OS LLmSecurity
mkdir -p /etc/HispanShield OS LLmSecurity/policies

chown -R aegis_agent:aegis /opt/HispanShield OS LLmSecurity
chmod 750 /opt/HispanShield OS LLmSecurity

# 3. Descarga del Modelo LLM Ligero Local (2B)
log "Iniciando descarga segura del modelo GenAI (Qwen2.5-1.5B/Gemma-2B GGUF)..."
python3 download_model.py

# 4. Instalando y securizando servicios
log "Instalando demonios systemd..."
cp ../os_base/sys_services/*.service /etc/systemd/system/
systemctl daemon-reload

log "InstalaciÃ³n completada. Por favor, revisa /etc/HispanShield OS LLmSecurity/policies antes de iniciar los servicios."
