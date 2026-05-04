#!/usr/bin/env python3
"""
HispanShield OS LLmSecurity: Secure Model Downloader
Downloads and verifies LLM models from STATE REPOSITORY (offline) with SHA256 checksum.
CWE-295 FIX: No insecure TLS, offline-only for classified models.
"""
import hashlib
import sys
import os
import argparse

# Model configurations: (URL, filename, SHA256, description)
# CWE-295 FIX: No HTTPS fallback - offline state repository only
MODELS = {
    "1.5b": {
        "url": "file:///opt/hispanshield/models/aegis-core-1.5b.gguf",
        "filename": "aegis-core-1.5b.gguf",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",  # SET REAL HASH
        "desc": "1.5B parameters - Edge devices (4GB RAM) - CLASSIFIED"
    },
    "7b": {
        "url": "file:///opt/hispanshield/models/aegis-core-7b.gguf",
        "filename": "aegis-core-7b.gguf",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",  # SET REAL HASH
        "desc": "7B parameters - Standard deployment (8GB RAM) - CLASSIFIED"
    },
    "military-7b": {
        "url": "file:///opt/hispanshield/models/aegis-military-7b-q5_k_m.gguf",
        "filename": "aegis-military-7b.gguf",
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",  # SET REAL HASH
        "desc": "7B Military Fine-Tuned - Sovereign Spanish defense - SECRETO"
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
    
    print(f"[+] Model: {MODEL_FILENAME}")
    print(f"[+] Description: {config['desc']}")
    print(f"[+] Source: {MODEL_URL}")
    
    model_path = os.path.join("/opt/hispanshield/models", MODEL_FILENAME)
    
    # CWE-295 FIX: Offline-only for state deployment
    if not os.path.exists(model_path):
        print(f"[!] Model not found: {model_path}")
        print(f"[!] Use sneakernet: Copy from state-signed USB to {model_path}")
        return False
    
    print(f"[+] Model found: {model_path}")
    
    # Verify SHA256
    print("[+] Verifying SHA256 checksum...")
    sha256_hash = hashlib.sha256()
    try:
        with open(model_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
    except Exception as e:
        print(f"[!] Error reading model: {e}")
        return False
    
    actual_hash = sha256_hash.hexdigest()
    print(f"[+] Expected: {EXPECTED_SHA256}")
    print(f"[+] Actual:   {actual_hash}")
    
    # Require real SHA256 (not placeholder)
    if EXPECTED_SHA256 == "0000000000000000000000000000000000000000000000000000000000000000":
        print("[!] WARNING: SHA256 not set.")
        print(f"[!] Run: sha256sum {model_path}")
        print("[!] Then update download_model.py with real hash.")
        response = input("Continue without hash verification? (yes/no): ")
        if response.lower() != "yes":
            return False
    elif actual_hash == EXPECTED_SHA256:
        print("[+] SHA256 verification PASSED")
        update_service_model(MODEL_FILENAME)
        return True
    else:
        print("[!] SHA256 verification FAILED - deleting corrupted file")
        os.remove(model_path)
        return False
    
    return True

def update_service_model(model_filename):
    service_file = "/etc/systemd/system/aegis-llm-runtime.service"
    if os.path.exists(service_file):
        try:
            with open(service_file, 'r') as f:
                content = f.read()
            content = content.replace(
                "aegis-core-1.5b.gguf",
                model_filename
            )
            with open(service_file, 'w') as f:
                f.write(content)
            print(f"[+] Updated service to use: {model_filename}")
        except Exception as e:
            print(f"[!] Error updating service: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download HispanShield LLM models (Offline State Repository)")
    parser.add_argument("--size", choices=["1.5b", "7b", "military-7b"], default="1.5b",
                        help="Model size (default: 1.5b)")
    args = parser.parse_args()
    
    if download_model(args.size):
        sys.exit(0)
    else:
        sys.exit(1)
