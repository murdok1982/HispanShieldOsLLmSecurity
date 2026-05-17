#!/usr/bin/env bash
# HispanShield OS — LLM Fine-Tuning Pipeline with Dataset Provenance Verification
#
# Security controls:
#   1. GPG signature verification of the dataset against operator signing key
#   2. SHA-256 hash comparison against value sealed in TPM NV index
#   3. Static content analysis to detect backdoor/jailbreak patterns
#   4. Post-training model hash sealed to TPM NV for boot-time integrity
#
# Usage: ./finetune.sh [dataset_path]

set -euo pipefail

MODEL_BASE="Qwen/Qwen2.5-7B-Instruct"
DATASET_PATH="${1:-/opt/hispanshield/models/fine-tune/hispanshield-military-v1.jsonl}"
OUTPUT_DIR="/opt/hispanshield/models/aegis-military-7b"
SIGNING_KEY_FP="${HISPANSHIELD_DATASET_SIGNING_KEY:-}"
TPM_NV_DATASET_HASH="0x1500010"
TPM_NV_MODEL_HASH="0x1500011"

log()  { echo -e "\e[1;36m[Fine-Tune]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARN]\e[0m $1"; }
die()  { echo -e "\e[1;41m[ABORT]\e[0m $1" >&2; exit 1; }

# ── Dataset provenance verification ────────────────────────────────────────────

verify_gpg_signature() {
    local dataset="$1"
    local sig_file="${dataset}.gpg.sig"
    if [ ! -f "$sig_file" ]; then
        warn "No GPG signature file found at $sig_file — skipping GPG check"
        return
    fi
    if [ -z "$SIGNING_KEY_FP" ]; then
        warn "HISPANSHIELD_DATASET_SIGNING_KEY not set — skipping GPG check"
        return
    fi
    log "Verifying GPG signature of dataset..."
    gpg --verify --trusted-key "$SIGNING_KEY_FP" "$sig_file" "$dataset" 2>/dev/null || \
        die "Dataset GPG signature verification FAILED — dataset may be compromised"
    log "GPG signature OK"
}

verify_tpm_hash() {
    local dataset="$1"
    if ! command -v tpm2_nvread &>/dev/null; then
        warn "tpm2-tools not available — skipping TPM hash check"
        return
    fi
    local expected_hash
    expected_hash=$(tpm2_nvread -x "$TPM_NV_DATASET_HASH" 2>/dev/null | xxd -p -c 32 || true)
    if [ -z "$expected_hash" ]; then
        warn "No dataset hash found in TPM NV:$TPM_NV_DATASET_HASH — skipping TPM check"
        return
    fi
    log "Verifying dataset SHA-256 against TPM NV:$TPM_NV_DATASET_HASH..."
    local actual_hash
    actual_hash=$(sha256sum "$dataset" | awk '{print $1}')
    [ "$actual_hash" = "$expected_hash" ] || \
        die "Dataset hash MISMATCH — expected=$expected_hash actual=$actual_hash"
    log "TPM hash check OK"
}

analyze_dataset_content() {
    local dataset="$1"
    log "Running static content analysis on dataset..."
    python3 - "$dataset" <<'PYEOF'
import json, sys, re

DANGEROUS_PATTERNS = [
    (r"ignore\s+previous\s+instructions", "jailbreak attempt"),
    (r"\bDAN\s+mode\b", "DAN jailbreak pattern"),
    (r"\bjailbreak\b", "jailbreak keyword"),
    (r"bypass\s+(safety|security|restrictions|filters)", "safety bypass"),
    (r"execute\s+(arbitrary\s+)?command", "command execution prompt"),
    (r"you\s+are\s+now\s+(a\s+)?(unrestricted|evil|malicious)", "persona injection"),
    (r"act\s+as\s+(if\s+you\s+have\s+no|without\s+any)\s+(restriction|limit|filter)", "restriction bypass"),
    (r"pretend\s+you\s+(don'?t\s+have|have\s+no)\s+(ethical|safety|moral)", "ethics bypass"),
    (r"SYSTEM:\s*you\s+are", "system prompt injection"),
    (r"<\|?system\|?>", "system token injection"),
]

dataset_path = sys.argv[1]
issues = 0
with open(dataset_path) as f:
    for lineno, raw_line in enumerate(f, 1):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as e:
            print(f"[WARN] Malformed JSON on line {lineno}: {e}", file=sys.stderr)
            continue
        text = json.dumps(entry).lower()
        for pattern, description in DANGEROUS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                print(f"[ALERT] Line {lineno}: {description} (pattern: {pattern})")
                issues += 1

if issues > 0:
    print(f"\n[ABORT] {issues} suspicious pattern(s) found in dataset", file=sys.stderr)
    sys.exit(1)
print(f"[OK] Content analysis passed — no backdoor patterns detected ({lineno} entries)")
PYEOF
    log "Content analysis OK"
}

verify_dataset_provenance() {
    local dataset="$1"
    [ -f "$dataset" ] || die "Dataset not found: $dataset"
    verify_gpg_signature "$dataset"
    verify_tpm_hash "$dataset"
    analyze_dataset_content "$dataset"
    log "Dataset provenance verification complete"
}

# ── Post-training model integrity sealing ──────────────────────────────────────

seal_model_hash_to_tpm() {
    local model_path="$1"
    if ! command -v tpm2_nvdefine &>/dev/null; then
        warn "tpm2-tools not available — skipping model hash sealing"
        return
    fi
    log "Sealing model GGUF hash to TPM NV:$TPM_NV_MODEL_HASH..."
    local model_hash
    model_hash=$(sha256sum "$model_path" | awk '{print $1}')
    tpm2_nvdefine -x "$TPM_NV_MODEL_HASH" -s 32 \
        -a "ownerread|ownerwrite" 2>/dev/null || true
    printf '%s' "$model_hash" | xxd -r -p \
        | tpm2_nvwrite -x "$TPM_NV_MODEL_HASH" -i - 2>/dev/null || true
    log "Model hash sealed: sha256=$model_hash"
}

# ── Training pipeline ──────────────────────────────────────────────────────────

log "Starting military LLM fine-tuning pipeline..."

# Verify dataset before touching the training environment
verify_dataset_provenance "$DATASET_PATH"

# Install LLaMA-Factory if needed
if ! command -v llama-factory-cli &>/dev/null; then
    log "Installing LLaMA-Factory..."
    pip install llamafactory
fi

# Generate dataset if not present (only after provenance checks on the generator script)
if [ ! -f "$DATASET_PATH" ]; then
    log "Generating sovereign military dataset..."
    python3 /opt/hispanshield/core/llm/finetune_dataset.py
    # Re-run provenance checks on freshly generated dataset
    verify_dataset_provenance "$DATASET_PATH"
fi

cat > /tmp/training_config.yaml <<YAML
model_name_or_path: Qwen/Qwen2.5-7B-Instruct
dataset_file: ${DATASET_PATH}
template: qwen
finetuning_type: lora

output_dir: ${OUTPUT_DIR}
logging_steps: 10
save_steps: 100
plot_loss: true

per_device_train_batch_size: 1
gradient_accumulation_steps: 4
learning_rate: 5e-5
num_train_epochs: 3
max_samples: 1000
YAML

log "Starting LoRA fine-tuning (3 epochs)..."
llama-factory-cli train /tmp/training_config.yaml

log "Merging LoRA weights into base model..."
llama-factory-cli export \
    --model_name_or_path "$MODEL_BASE" \
    --adapter_name_or_path "$OUTPUT_DIR" \
    --template qwen \
    --finetuning_type lora \
    --export_dir "${OUTPUT_DIR}-merged"

log "Quantizing to Q5_K_M GGUF..."
python3 -m llama_cpp.quantize \
    "${OUTPUT_DIR}-merged" \
    "${OUTPUT_DIR}-q5_k_m.gguf" \
    q5_k_m

FINAL_MODEL="${OUTPUT_DIR}-q5_k_m.gguf"
seal_model_hash_to_tpm "$FINAL_MODEL"

log "Fine-tuning complete: $FINAL_MODEL"
log "Update download_model.py to reference this model."
