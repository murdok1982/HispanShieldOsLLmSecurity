#!/usr/bin/env bash
# HispanShield OS - LLM Fine-Tuning Script (Military Domain)
# Fine-tunes Qwen2.5-7B-Instruct using LLaMA-Factory

set -euo pipefail

MODEL_BASE="Qwen/Qwen2.5-7B-Instruct"
DATASET_PATH="/opt/hispanshield/models/fine-tune/hispanshield-military-v1.jsonl"
OUTPUT_DIR="/opt/hispanshield/models/aegis-military-7b"

log() { echo -e "\e[1;36m[Fine-Tune]\e[0m $1"; }

log "Starting military LLM fine-tuning..."

# Install LLaMA-Factory
if ! command -v llama-factory-cli &> /dev/null; then
    log "Installing LLaMA-Factory..."
    pip install llamafactory
fi

# Generate dataset if not exists
if [ ! -f "$DATASET_PATH" ]; then
    log "Generating sovereign military dataset..."
    python3 /opt/hispanshield/core/llm/finetune_dataset.py
fi

# Fine-tuning configuration
cat > /tmp/training_config.yaml << 'YAML'
model_name_or_path: Qwen/Qwen2.5-7B-Instruct
dataset_file: /opt/hispanshield/models/fine-tune/hispanshield-military-v1.jsonl
template: qwen
finetuning_type: lora

output_dir: /opt/hispanshield/models/aegis-military-7b
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

# Merge LoRA weights and quantize
log "Merging LoRA weights into base model..."
llama-factory-cli export \
    --model_name_or_path $MODEL_BASE \
    --adapter_name_or_path $OUTPUT_DIR \
    --template qwen \
    --finetuning_type lora \
    --export_dir "${OUTPUT_DIR}-merged"

# Quantize to Q5_K_M for deployment
log "Quantizing to Q5_K_M GGUF..."
python3 -m llama_cpp.quantize \
    "${OUTPUT_DIR}-merged" \
    "${OUTPUT_DIR}-q5_k_m.gguf" \
    q5_k_m

log "Fine-tuning complete: ${OUTPUT_DIR}-q5_k_m.gguf"
log "Update download_model.py to use this model."
