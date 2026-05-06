#!/usr/bin/env bash
# Seal Aegis audit logs and trusted binaries with fs-verity so any tamper
# (truncate, mid-file rewrite, swap-with-fake) makes the file unreadable
# rather than silently passing.
#
# Requirements:
#   - kernel >= 5.4 with CONFIG_FS_VERITY=y
#   - filesystem support: ext4 (with -O verity) or btrfs (>= 5.15)
#   - userspace tool: fsverity-utils
#
# Usage: bash fs-verity-setup.sh [--check]
#
# --check: only verifies existing measurements against /etc/hispanshield/fsverity.digests

set -euo pipefail

DIGEST_FILE="${HISPANSHIELD_FSVERITY_DIGESTS:-/etc/hispanshield/fsverity.digests}"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

log() { echo -e "\e[1;36m[fs-verity]\e[0m $*"; }
err() { echo -e "\e[1;41m[ERROR]\e[0m $*" >&2; }

if ! command -v fsverity >/dev/null 2>&1; then
    err "fsverity-utils not installed (apt: fsverity-utils)"
    exit 2
fi

# Files to seal: append-only audit log + Aegis trusted binaries.
TARGETS=(
    /var/log/audit/audit.log
    /opt/hispanshield/core/rust/target/release/aegis-sentinel
    /opt/hispanshield/core/rust/target/release/aegis-gatekeeper
    /opt/hispanshield/bin/llama-server
)

if [ "$CHECK_ONLY" -eq 1 ]; then
    if [ ! -r "$DIGEST_FILE" ]; then
        err "No baseline digest file at $DIGEST_FILE"
        exit 3
    fi
    fail=0
    while IFS=' ' read -r expected path; do
        actual=$(fsverity measure "$path" 2>/dev/null | awk '{print $1}') || actual=""
        if [ "$actual" != "$expected" ]; then
            err "DRIFT $path expected=$expected actual=${actual:-MISSING}"
            fail=1
        fi
    done < "$DIGEST_FILE"
    [ "$fail" -eq 0 ] && log "All measurements match baseline." || exit 4
    exit 0
fi

log "Enabling fs-verity on Aegis trust roots..."
mkdir -p "$(dirname "$DIGEST_FILE")"
: > "${DIGEST_FILE}.new"
for t in "${TARGETS[@]}"; do
    [ -e "$t" ] || { log "Skipping missing $t"; continue; }
    if ! fsverity enable "$t" 2>/dev/null; then
        # Already enabled, or filesystem does not support fs-verity.
        :
    fi
    measurement=$(fsverity measure "$t" | awk '{print $1}')
    printf '%s %s\n' "$measurement" "$t" >> "${DIGEST_FILE}.new"
    log "  $t  ->  $measurement"
done
mv "${DIGEST_FILE}.new" "$DIGEST_FILE"
chmod 0440 "$DIGEST_FILE"
log "Baseline written to $DIGEST_FILE"
log "Run with --check periodically (cron, or tied to integrity monitor)."
