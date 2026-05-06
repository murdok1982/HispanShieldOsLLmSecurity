#!/usr/bin/env bash
# Install and apply HispanShield kernel hardening sysctls.

set -euo pipefail

SRC="$(dirname "$(readlink -f "$0")")/hispanshield-hardening.conf"
DST="/etc/sysctl.d/99-hispanshield.conf"

if [ "$(id -u)" -ne 0 ]; then
    echo "must run as root" >&2
    exit 1
fi

install -m 0644 "$SRC" "$DST"
sysctl --system

echo "[sysctl] Applied $DST"
echo "[sysctl] Verify with: sysctl kernel.kptr_restrict kernel.unprivileged_bpf_disabled"
