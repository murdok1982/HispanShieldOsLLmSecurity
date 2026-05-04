# Cross-Domain Solution (CDS) Guard Service (FIXED - No OPSEC leaks)
# Manages secure data transfers between classification levels.
# CWE-FIX: Removed external CA references, using state PKI only.

set -euo pipefail;

log() { echo -e "\e[1;34m[CDS Guard]\e[0m $1"; }

CDS_CONFIG="/etc/hispanshield/cds"
mkdir -p "$CDS_CONFIG"

# Install CDS dependencies (internal only)
install_cds_deps() {
    log "Installing CDS dependencies (internal only)..."
    apt-get update && apt-get install -y \
        clamav \
        clamav-daemon \
        libmagic1 \
        file
    log "CDS dependencies installed"
}

# Configure content scanner (state-only rules)
setup_content_scanner() {
    log "Setting up content scanner..."
    cat > "$CDS_CONFIG/content-scanner.conf" << 'CONF'
# CDS Content Scanner Configuration
# Scans for: malware, classification markers, sensitive keywords

[scanner]
clamav_socket = /var/run/clamav/clamd.ctl
magic_file = /usr/share/file/magic.mgc

[keywords]
sensitive = INTERNAL_SENSITIVE_MARKERS
classification_markers = NOFORN, RESTRICTED, TOP SECRET

[actions]
on_malware = block
on_misclassification = quarantine
on_sensitive_leak = alert
CONF
    log "Content scanner configured (internal markers only)"
}

# Configure dual-approval workflow (no external refs)
setup_approval_workflow() {
    log "Setting up dual-approval workflow..."
    cat > "$CDS_CONFIG/approval-workflow.json" << 'JSON'
{
    "transfer_rules": {
        "Confidencial_to_Secreto": {
            "requires_approval": true,
            "approvers_required": 1,
            "justification_required": false
        },
        "Secreto_to_Confidencial": {
            "requires_approval": true,
            "approvers_required": 2,
            "justification_required": true,
            "max_data_size_mb": 10
        },
        "AltoSecreto_to_any": {
            "requires_approval": true,
            "approvers_required": 2,
            "justification_required": true,
            "max_data_size_mb": 1,
            "encryption_required": true
        }
    },
    "guards": [
        "malware_scan",
        "classification_check",
        "keyword_filter",
        "metadata_strip"
    ]
}
JSON
    log "Approval workflow configured"
}

# Create CDS guard systemd service
create_cds_service() {
    log "Creating CDS guard service..."
    cat > /etc/systemd/system/aegis-cds-guard.service << 'SERVICE'
[Unit]
Description=Aegis CDS Guard (Cross-Domain Solution)
After=aegis-agent-core.service
Wants=aegis-agent-core.service

[Service]
Type=simple
User=aegis_admin
WorkingDirectory=/opt/hispanshield/core/rust/aegis-sentinel
ExecStart=/opt/hispanshield/core/rust/target/release/aegis-sentinel cds-guard
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
SystemCallFilter=~@mount @raw-io @debug @privileged

[Install]
WantedBy=multi-user.target
SERVICE

    systemctl daemon-reload
    log "CDS guard service created"
}

# Main
log "Setting up Cross-Domain Solution (CDS) - No external refs..."
install_cds_deps
setup_content_scanner
setup_approval_workflow
create_cds_service

log "CDS setup complete. Start with: systemctl start aegis-cds-guard"
