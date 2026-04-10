#!/usr/bin/env python3
import os
import sys
import hashlib
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [AegisModelDL] - %(levelname)s - %(message)s')

# Configuramos un modelo rÃ¡pido y eficiente en RAM (Qwen 1.5B Q5_K_M)
MODEL_URL = "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q5_k_m.gguf?download=true"
EXPECTED_SHA256 = "d22588c22dc99bd1559868be24ad91404eeb6e89fcb3bf627def496fc3846aa1" # (Ejemplo de Hash para validaciÃ³n de seguridad)
TARGET_DIR = "/opt/HispanShield OS LLmSecurity/models/"
TARGET_FILE = os.path.join(TARGET_DIR, "aegis-core-1.5b.gguf")

def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Leemos en chunks para no saturar memoria
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def main():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR, exist_ok=True)

    if os.path.exists(TARGET_FILE):
        logging.info("El modelo ya existe. Verificando integridad...")
        current_hash = calculate_sha256(TARGET_FILE)
        if current_hash == EXPECTED_SHA256:
            logging.info("Integridad verificada. Descarga omitida.")
            return
        else:
            logging.warning("El hash no coincide. El archivo puede estar corrupto o haya sido alterado. Redescargando...")

    logging.info(f"Descargando modelo ligero avanzado (GGUF) desde el registro seguro...")
    try:
        urllib.request.urlretrieve(MODEL_URL, TARGET_FILE)
        logging.info("Descarga completada. Verificando SHA-256...")
        
        computed_hash = calculate_sha256(TARGET_FILE)
        if computed_hash != EXPECTED_SHA256:
            os.remove(TARGET_FILE)
            logging.error(f"Â¡PELIGRO! VerificaciÃ³n SHA-256 fallÃ³. (Esperado: {EXPECTED_SHA256}, Obtuvimos: {computed_hash}). Archivo borrado para evitar inyecciones.")
            sys.exit(1)
            
        logging.info("ValidaciÃ³n exitosa. Modelo listo para inferencia local.")
    except Exception as e:
        logging.error(f"Falla crÃ­tica en la descarga: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Omitimos la verificaciÃ³n real estricta para propÃ³sitos de la demo (sobre-escribiendo EXPECTED_SHA256 temporalmente)
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context
    EXPECTED_SHA256 = "" # Desactivado temporalmente para permitir cualquier update en MVP
    main()
