#!/usr/bin/env bash
# HispanShield OS - AI Firewall (Zero-Trust Model)
# Blindaje contra Prompt Injection y Data Poisoning

set -euo pipefail

log() { echo -e "\e[1;34m[AI Firewall]\e[0m $1"; }

log "Configurando aislamiento estocástico para Qwen2.5 (Fase 3)..."

# 1. NeMo Guardrails / Filtro de entrada
cat > core/ai_firewall/guardrails.yml << 'GUARDRAILS'
models:
  - type: main
    engine: llama.cpp
    model: qwen2.5-military

rails:
  input:
    flows:
      - check_jailbreak
      - check_prompt_injection
      - sanitize_logs
  output:
    flows:
      - check_hallucination
      - verify_no_secrets
GUARDRAILS

# 2. Perfil AppArmor super-restringido para inferencia LLM
cat > os_base/apparmor/opt.hispanshield.ai.llm-inference << 'LLM_APPARMOR'
#include <tunables/global>

/opt/hispanshield/bin/llama-server {
    #include <abstractions/base>
    
    # Solo acceso de lectura al modelo
    /opt/hispanshield/models/aegis-military*.gguf r,
    
    # Red estrictamente local para el API (IPC)
    network inet stream,
    deny network inet6,
    deny network raw,
    
    # No puede escribir a disco ni ejecutar binarios
    deny /** w,
    deny /** x,
    
    # IPC solo via socket designado
    /run/aegis-ai.sock rw,
}
LLM_APPARMOR

log "AI Firewall configurado."
