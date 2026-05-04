#!/usr/bin/env python3
"""
HispanShield OS - Military Cybersecurity LLM Fine-Tuning
Fine-tunes Qwen2.5-7B-Instruct for military/cybersecurity domain expertise.
Uses sovereign Spanish dataset curated for state defense purposes.
"""
import json
import os
from pathlib import Path

# Sovereign Military/Cybersecurity Dataset (Spanish)
MILITARY_CYBER_KEYWORDS = [
    "seguridad nacional", "defensa cibernética", "TTPs", "MITRE ATT&CK",
    "análisis de amenazas", "inteligencia de amenazas", "respuesta a incidentes",
    "honeypots", "engaño", "atribución", "guerra cibernética",
    "clasificación de documentos", "secreto", "confidencial", "alto secreto",
    "auditoría de seguridad", "cumplimiento", "NIST", "ICD 503", "STIG",
    "cifrado FIPS 140-3", "TPM", "Secure Boot", "MLS", "Bell-La Padula"
]

def create_fine_tuning_dataset():
    """Create sovereign Spanish military/cybersecurity dataset"""
    dataset = []
    
    # System prompts for military context
    system_prompts = [
        "Eres Aegis, sistema de defensa cibernética de nivel estatal. Proporciona análisis técnico experto.",
        "Asistente de seguridad nacional. Evalúa amenazas con criterios militares clasificados.",
        "Analista de inteligencia de amenazas. Identifica TTPs y vectores de ataque sofisticados."
    ]
    
    # Training examples: Q&A for military cybersecurity
    training_examples = [
        {
            "instruction": "Analiza la telemetría: CPU 95%, RAM 90%, 500 conexiones externas establecidas. ¿Qué acción tomar?",
            "response": "ALERTA CRÍTICA: Posible compromiso activo. Acciones: 1) Aislar red inmediatamente, 2) Bloquear IPs externas, 3) Activar protocolo de respuesta a incidentes, 4) Notificar al SOC estatal, 5) Preservar evidencia forense."
        },
        {
            "instruction": "¿Cómo implementar Multi-Level Security (MLS) siguiendo Bell-La Padula en un sistema Linux?",
            "response": "Implementación MLS: 1) Instalar SELinux en modo MLS, 2) Definir niveles: Confidencial=100, Secreto=200, Alto_Secreto=300, 3) Etiquetar archivos con nivel, 4) Aplicar reglas: No-leer-arriba (cpu>=suje), No-escribir-abajo (cpu<=objeto), 5) Configurar usuarios con clearance matching."
        },
        {
            "instruction": "Ejecutar escaneo de vulnerabilidades con Nuclei para infraestructura crítica. ¿Qué consideraciones de cumplimiento aplican?",
            "response": "Para escaneo autorizado en infraestructura crítica: 1) Obtener autorización por escrito, 2) Notificar al CERT nacional, 3) Usar templates aprobados, 4) Cumplir con NIST SP 800-53 (RA-5), 5) Documentar en auditoría, 6) Aplicar parches según SLA clasificado."
        },
        {
            "instruction": "Configurar TPM 2.0 para sellado de claves LUKS en sistema militar. Pasos técnicos.",
            "response": "Configuración TPM+LUKS: 1) tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx, 2) tpm2_create -C primary.ctx -u key.pub -r key.priv, 3) Extraer clave: tpm2_readpublic -c key.ctx -o key.pem, 4) Configurar crypttab: luks,keyscript=/usr/sbin/tpm-luks-script, 5) Verificar: cryptsetup luksOpen --test-passphrase."
        },
        {
            "instruction": "Detectar y responder a ataque APT contra cadena de suministro de software estatal.",
            "response": "Respuesta APT cadena suministro: 1) Generar SBOM inmediato, 2) Verificar firmas PGP de todos los paquetes, 3) Escanear con antivirus militar actualizado, 4) Comparar hashes con repositorio oficial, 5) Activar honeypots para atribución, 6) Coordinar con agencias de inteligencia."
        }
    ]
    
    # Generate dataset in Alpaca format
    for example in training_examples:
        for sys_prompt in system_prompts:
            dataset.append({
                "instruction": example["instruction"],
                "input": "",
                "output": f"{sys_prompt}\n\n{example['response']}"
            })
    
    # Add keyword-based Q&A
    for keyword in MILITARY_CYBER_KEYWORDS:
        dataset.append({
            "instruction": f"Explica el concepto de '{keyword}' en contexto militar/ciberseguridad.",
            "input": "",
            "output": f"Concepto estatal: {keyword}. Aplicación: Protocolos de defensa nacional, implementación técnica según estándares militarizados, cumplimiento normativo correspondiente."
        })
    
    return dataset

def save_dataset(dataset, output_path):
    """Save dataset in JSONL format for fine-tuning"""
    with open(output_path, 'w', encoding='utf-8') as f:
        for item in dataset:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')
    print(f"[+] Dataset saved: {output_path} ({len(dataset)} examples)")

if __name__ == "__main__":
    print("[+] Generating sovereign Spanish military/cybersecurity dataset...")
    dataset = create_fine_tuning_dataset()
    
    output_dir = Path("/opt/hispanshield/models/fine-tune")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    save_dataset(dataset, output_dir / "hispanshield-military-v1.jsonl")
    print("[+] Fine-tuning dataset ready. Use with: llama-factory-cli train...")
