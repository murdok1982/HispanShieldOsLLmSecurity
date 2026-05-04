#!/usr/bin/env bash
# Remove false classification from repo (L1 FIX)
# Changes "SECRETO" → "UNCLASSIFIED" in all files

set -euo pipefail;

log() { echo -e "\e[1;36m[Legal Fix]\e[0m $1"; }

log "Removing false classification markers..."

# Replace in README
if [ -f README.md ]; then
    sed -i 's/SECRETO/UNCLASSIFIED/g' README.md
    sed -i 's/ALTO SECRETO/UNCLASSIFIED/g' README.md
    sed -i 's/NOFORN//g' README.md
    log "README.md: Classification downgraded to UNCLASSIFIED"
fi

# Replace in architecture docs
if [ -f docs/architecture/ARCHITECTURE_MILITAR.md ]; then
    sed -i 's/SECRETO/UNCLASSIFIED/g' docs/architecture/ARCHITECTURE_MILITAR.md
    sed -i 's/ALTO SECRETO/UNCLASSIFIED/g' docs/architecture/ARCHITECTURE_MILITAR.md
    log "ARCHITECTURE_MILITAR.md: Classification fixed"
fi

# Replace in FINAL_REPORT.md
if [ -f FINAL_REPORT.md ]; then
    sed -i 's/SECRETO/UNCLASSIFIED/g' FINAL_REPORT.md
    sed -i 's/ALTO SECRETO/UNCLASSIFIED/g' FINAL_REPORT.md
    log "FINAL_REPORT.md: Classification fixed"
fi

# Replace in Rust source files
log "Scanning source files..."
find core/ -type f -name "*.rs" -o -name "*.toml" | while read file; do
    sed -i 's/SECRETO/UNCLASSIFIED/g' "$file" 2>/dev/null || true
    sed -i 's/ALTO SECRETO/UNCLASSIFIED/g' "$file" 2>/dev/null || true
done

log "False classification removed. System is now UNCLASSIFIED / PoC."
log "WARNING: Do NOT use 'SECRETO' or 'ALTO SECRETO' until formal classification is granted."
