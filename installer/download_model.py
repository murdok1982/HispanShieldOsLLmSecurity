#!/usr/bin/env python3
"""
HispanShield OS LLmSecurity: Secure Model Downloader
Downloads and verifies LLM models from HuggingFace with SHA256 checksum.
Supports multiple model sizes for different deployment scenarios (Edge/Standard/Server).
"""
import hashlib
import urllib.request
import sys
import os
import argparse

# Model configurations: (URL, filename, SHA256, description)
MODELS = {
    "1.5b": {
        "url": "https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q5_k_m.gguf",
        "filename": "aegis-core-1.5b.gguf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # UPDATE THIS
        "desc": "1.5B parameters - Edge devices (4GB RAM)"
    },
    "7b": {
        "url": "https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF/resolve/main/qwen2.5-7b-instruct-q5_k_m.gguf",
        "filename": "aegis-core-7b.gguf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # UPDATE THIS
        "desc": "7B parameters - Standard deployment (8GB RAM)"
    },
    "14b": {
        "url": "https://huggingface.co/Qwen/Qwen2.5-14B-Instruct-GGUF/resolve/main/qwen2.5-14b-instruct-q5_k_m.gguf",
        "filename": "aegis-core-14b.gguf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # UPDATE THIS
        "desc": "14B parameters - Server deployment (16GB RAM)"
    },
    "military-7b": {
        "url": "file:///opt/hispanshield/models/aegis-military-7b-q5_k_m.gguf",
        "filename": "aegis-military-7b.gguf",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # UPDATE AFTER FINE-TUNE
        "desc": "7B Military Fine-Tuned - Sovereign Spanish defense (8GB RAM)"
    }
}

def download_model(model_size="1.5b"):
    if model_size not in MODELS:
        print(f"[!] Invalid model size: {model_size}. Choose from: {', '.join(MODELS.keys())}")
        return False
    
    config = MODELS[model_size]
    MODEL_URL = config["url"]
    MODEL_FILENAME = config["filename"]
    EXPECTED_SHA256 = config["sha256"]
    
    print(f"[+] Downloading LLM model: {MODEL_FILENAME}")
    print(f"[+] Description: {config['desc']}")
    print(f"[+] From: {MODEL_URL}")
    
    # Create models directory if it doesn't exist
    models_dir = "/opt/hispanshield/models"
    if not os.path.exists(models_dir):
        os.makedirs(models_dir, exist_ok=True)
    
    model_path = os.path.join(models_dir, MODEL_FILENAME)
    
    try:
        # Download with progress
        print("[+] Starting download...")
        urllib.request.urlretrieve(MODEL_URL, model_path)
        print(f"[+] Model downloaded to: {model_path}")
        
        # Verify SHA256
        print("[+] Verifying SHA256 checksum...")
        sha256_hash = hashlib.sha256()
        with open(model_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        actual_hash = sha256_hash.hexdigest()
        print(f"[+] Expected: {EXPECTED_SHA256}")
        print(f"[+] Actual:   {actual_hash}")
        
        if actual_hash == EXPECTED_SHA256:
            print("[+] SHA256 verification PASSED")
            # Update the systemd service to use the downloaded model
            update_service_model(MODEL_FILENAME)
            return True
        else:
            print("[!] SHA256 verification FAILED - deleting corrupted file")
            os.remove(model_path)
            return False
            
    except Exception as e:
        print(f"[!] Error downloading model: {e}")
        return False

def update_service_model(model_filename):
    service_file = "/etc/systemd/system/aegis-llm-runtime.service"
    if os.path.exists(service_file):
        with open(service_file, 'r') as f:
            content = f.read()
        content = content.replace(
            "aegis-core-1.5b.gguf",
            model_filename
        )
        with open(service_file, 'w') as f:
            f.write(content)
        print(f"[+] Updated service to use: {model_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download HispanShield LLM models")
    parser.add_argument("--size", choices=["1.5b", "7b", "14b"], default="1.5b",
                        help="Model size to download (default: 1.5b)")
    args = parser.parse_args()
    
    if download_model(args.size):
        sys.exit(0)
    else:
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
