#!/usr/bin/env bash
# HispanShield OS — C2 Channel Setup (Spectre)
#
# This script is a thin wrapper that delegates to the canonical C2 implementation
# at core/c2/spectre_c2.sh. Authorization and execution are enforced there.
#
# Usage: ./setup_c2.sh {setup|start|stop|status|provision-token}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SPECTRE_C2="${REPO_ROOT}/core/c2/spectre_c2.sh"

if [ ! -x "$SPECTRE_C2" ]; then
    chmod +x "$SPECTRE_C2"
fi

exec "$SPECTRE_C2" "$@"
