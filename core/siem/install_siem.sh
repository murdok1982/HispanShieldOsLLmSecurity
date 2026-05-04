#!/usr/bin/env bash
# HispanShield OS - SIEM Integration Module (State SOC)
# Forwards audit logs to ELK/Splunk via mutual TLS

set -euo pipefail

log() { echo -e "\e[1;36m[SIEM Integration]\e[0m $1"; }

# Install SIEM forwarder (Filebeat for ELK, Splunk Universal Forwarder as alternative)
install_siem_forwarder() {
    log "Installing SIEM forwarder (Filebeat)..."
    apt-get update && apt-get install -y filebeat
    
    # Configure Filebeat for HispanShield logs
    cat > /etc/filebeat/filebeat.yml << 'FILEBEAT'
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/hispanshield/*.log
      - /var/log/audit/audit.log
    fields:
      env: "military"
      system: "hispanshield"
    fields_under_root: false

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_cloud_metadata: ~
  - add_docker_metadata: ~

output.elasticsearch:
  hosts: ["https://siem-state.intranet:9200"]
  username: "${SIEM_USER}"
  password: "${SIEM_PASSWORD}"
  ssl:
    certificate_authorities: ["/etc/hispanshield/pki/ca.crt"]
    certificate: "/etc/hispanshield/pki/filebeat.crt"
    key: "/etc/hispanshield/pki/filebeat.key"
  ssl.verification_mode: "certificate"

logging.level: info
FILEBEAT

    systemctl enable filebeat
    log "Filebeat configured for SIEM integration"
}

# Configure mutual TLS for log forwarding
configure_mtls() {
    log "Configuring mutual TLS for SIEM..."
    mkdir -p /etc/hispanshield/pki
    
    # Generate client certificate for this node (self-signed for demo, use state PKI in production)
    openssl genrsa -out /etc/hispanshield/pki/filebeat.key 2048
    openssl req -new -key /etc/hispanshield/pki/filebeat.key \
        -out /etc/hispanshield/pki/filebeat.csr \
        -subj "/CN=hispanshield-node/O=StateMilitary/C=ES"
    openssl x509 -req -days 365 -in /etc/hispanshield/pki/filebeat.csr \
        -signkey /etc/hispanshield/pki/filebeat.key \
        -out /etc/hispanshield/pki/filebeat.crt
    
    # Copy CA certificate (in production, use state-provided CA)
    cp /etc/hispanshield/pki/filebeat.crt /etc/hispanshield/pki/ca.crt
    
    chmod 600 /etc/hispanshield/pki/filebeat.key
    chmod 644 /etc/hispanshield/pki/filebeat.crt
    
    log "Mutual TLS configured"
}

# Setup HA Failover with Corosync/Pacemaker
setup_ha_failover() {
    log "Setting up High Availability failover..."
    apt-get install -y corosync pacemaker pcs
    
    # Configure Corosync
    cat > /etc/corosync/corosync.conf << 'COROSYNC'
totem {
    version: 2
    secauth: on
    threads: 0
    interface {
        ringnumber: 0
        bindnetaddr: 192.168.100.0
        mcastaddr: 239.255.1.1
        mcastport: 5405
    }
}

logging {
    to_logfile: yes
    logfile: /var/log/corosync.log
    to_syslog: yes
}

quorum {
    provider: corosync_votequorum
    expected_votes: 2
}
COROSYNC

    # Enable and start services
    systemctl enable corosync pacemaker
    
    log "HA Failover configured. Use 'pcs cluster setup' to join nodes."
}

# Main
log "Starting SIEM + HA integration for State SOC..."
configure_mtls
install_siem_forwarder
setup_ha_failover
log "SIEM integration complete. Logs will be forwarded to State SOC."
