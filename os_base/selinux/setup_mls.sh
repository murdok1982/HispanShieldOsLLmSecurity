#!/usr/bin/env bash
# Configure SELinux MLS for HispanShield OS state-military deployment.
#
# Fase 2 hardening: this no longer ships only "informational" .conf files.
# It compiles and installs the real policy module aegis-mls.te (Bell-La Padula
# constraints + custom domains + file contexts), then validates with seinfo.

set -euo pipefail

log()  { echo -e "\e[1;35m[MLS/SELinux]\e[0m $1"; }
warn() { echo -e "\e[1;33m[WARNING]\e[0m $1" >&2; }
err()  { echo -e "\e[1;41m[ERROR]\e[0m $1" >&2; exit 1; }

POLICY_DIR="${POLICY_DIR:-/opt/hispanshield/os_base/selinux}"

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || err "missing command: $1 (install $2)"
}

install_selinux_mls() {
    log "Ensuring SELinux MLS toolchain is installed..."
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y selinux-policy-mls audit policycoreutils \
            policycoreutils-python-utils setools-console checkpolicy
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update
        apt-get install -y selinux-policy-mls auditd policycoreutils \
            policycoreutils-python-utils setools checkpolicy semodule-utils
    else
        warn "Unknown package manager; install SELinux MLS toolchain manually."
    fi
    sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=mls/' /etc/selinux/config
}

compile_policy() {
    log "Compiling aegis-mls policy module..."
    require_cmd checkmodule "checkpolicy package"
    require_cmd semodule_package "policycoreutils package"
    require_cmd semodule "policycoreutils package"

    pushd "$POLICY_DIR" >/dev/null
    checkmodule -M -m -o aegis-mls.mod aegis-mls.te
    semodule_package -o aegis-mls.pp -m aegis-mls.mod -f aegis-mls.fc
    semodule -i aegis-mls.pp
    popd >/dev/null

    log "aegis-mls module installed."
}

apply_file_contexts() {
    log "Applying SELinux file contexts..."
    restorecon -RFv /opt/hispanshield  || true
    restorecon -RFv /var/log/hispanshield 2>/dev/null || true
    restorecon -RFv /var/lib/hispanshield 2>/dev/null || true
    restorecon -RFv /etc/hispanshield/secrets 2>/dev/null || true
}

setup_user_clearances() {
    log "Configuring user clearances..."
    semanage login -a -s staff_u -r s0     aegis_agent  || true
    semanage login -m -s staff_u -r s1     aegis_admin  2>/dev/null \
        || semanage login -a -s staff_u -r s1 aegis_admin || true
    semanage login -m -s staff_u -r s0-s2  root         2>/dev/null \
        || semanage login -a -s staff_u -r s0-s2 root    || true
}

verify() {
    log "Verifying policy is loaded..."
    if seinfo -t 2>/dev/null | grep -q '^   aegis_exec_t$'; then
        log "OK  aegis_exec_t present"
    else
        err "aegis_exec_t not present in policy — installation failed"
    fi
    if seinfo -t 2>/dev/null | grep -q '^   aegis_secret_t$'; then
        log "OK  aegis_secret_t present"
    else
        err "aegis_secret_t not present"
    fi
    log "Policy loaded. Reboot to activate MLS mode (and verify with: sestatus, id -Z)."
}

main() {
    if [ "$(id -u)" -ne 0 ]; then
        err "must run as root"
    fi
    install_selinux_mls
    compile_policy
    apply_file_contexts
    setup_user_clearances
    verify
}

main "$@"
