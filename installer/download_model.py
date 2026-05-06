#!/usr/bin/env python3
"""
HispanShield OS LLmSecurity: Secure Model Downloader
Downloads and verifies LLM models from STATE REPOSITORY (offline) with SHA256 checksum.
CWE-295 FIX: No insecure TLS, offline-only for classified models.
"""
import hashlib
import sys
import os
import json
import tempfile
import argparse
from datetime import datetime, timezone

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
    
    # Fail closed: a placeholder hash means the model has not been provisioned
    # by the state signing process and must not be loaded. Interactive bypass
    # has been removed (CWE-345) — no operator key-stroke can downgrade integrity.
    if EXPECTED_SHA256 == "0000000000000000000000000000000000000000000000000000000000000000":
        print(f"[!] FATAL: SHA256 placeholder for {model_size}.")
        print(f"[!] Compute the hash on the air-gapped signing host and pin it in MODELS[].")
        print(f"[!]   sha256sum {model_path}")
        return False

    if actual_hash == EXPECTED_SHA256:
        print("[+] SHA256 verification PASSED")
        update_service_model(MODEL_FILENAME)
        write_runtime_info(MODEL_FILENAME, model_size, actual_hash)
        return True

    print("[!] SHA256 verification FAILED - deleting corrupted file")
    os.remove(model_path)
    return False


# Default location of the runtime descriptor consumed by the Tauri shell
# (see ui/aegis-desktop/src-tauri/src/main.rs::runtime_info). The env var
# below mirrors HISPANSHIELD_RUNTIME_INFO_PATH on the Rust side so test rigs
# can redirect to a tmpfs path.
DEFAULT_RUNTIME_INFO_PATH = "/etc/hispanshield/runtime.json"
ENV_RUNTIME_INFO_PATH = "HISPANSHIELD_RUNTIME_INFO_PATH"


def write_runtime_info(model_filename, model_size, sha256_hex):
    """Materialize /etc/hispanshield/runtime.json atomically.

    The desktop UI reads this descriptor to decide whether the LLM stack is
    provisioned. Failure here MUST NOT fail the download (the model itself
    is already verified on disk); it degrades to a warning so an operator
    can re-run the materialization step manually.
    """
    target = os.environ.get(ENV_RUNTIME_INFO_PATH, DEFAULT_RUNTIME_INFO_PATH)
    payload = {
        "model": model_filename,
        "size": model_size,
        "sha256": sha256_hex,
        "provisioned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "provisioned",
    }
    try:
        parent = os.path.dirname(target) or "."
        os.makedirs(parent, exist_ok=True)
        # Atomic write: tmp file in the same directory + fsync + rename so a
        # crash mid-write cannot leave a half-serialized JSON for the UI.
        fd, tmp_path = tempfile.mkstemp(prefix=".runtime-", suffix=".json.tmp", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            # 0o644: the UI runs as aegis_admin (non-root) and only needs read.
            os.chmod(tmp_path, 0o644)
            os.replace(tmp_path, target)
        except Exception:
            # Best-effort cleanup of the staging file on failure.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        print(f"[+] Runtime descriptor written: {target}")
    except Exception as e:
        # Graceful downgrade — the download itself succeeded.
        print(f"[!] WARNING: could not materialize runtime descriptor at {target}: {e}")

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
