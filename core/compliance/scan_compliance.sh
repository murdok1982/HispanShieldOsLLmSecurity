#!/usr/bin/env bash
# HispanShield OS - Compliance Scanner.
#
# Fase 2 upgrade: when OpenSCAP is installed, run the official ssgproject STIG
# profile and store the XCCDF report alongside the heuristic JSON checks. The
# heuristic checks remain so the operator can run a quick smoke-test on systems
# that don't (yet) have OpenSCAP, but they are no longer the primary signal.

set -euo pipefail

log()  { echo -e "\e[1;33m[Compliance]\e[0m $1"; }
pass() { echo -e "  \e[32m[PASS]\e[0m $1"; }
fail() { echo -e "  \e[31m[FAIL]\e[0m $1"; }
warn() { echo -e "  \e[33m[WARN]\e[0m $1" >&2; }

RESULTS_DIR="${HISPANSHIELD_COMPLIANCE_DIR:-/var/log/hispanshield/compliance}"
mkdir -p "$RESULTS_DIR"

run_openscap_stig() {
    if ! command -v oscap >/dev/null 2>&1; then
        warn "OpenSCAP not installed (apt: openscap-scanner libopenscap8 ssg-debian); skipping authoritative STIG run."
        return 0
    fi

    local content="/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml"
    if [ ! -r "$content" ]; then
        # Try common alternates.
        for alt in /usr/share/xml/scap/ssg/content/ssg-*-ds.xml; do
            [ -r "$alt" ] && content="$alt" && break
        done
    fi
    if [ ! -r "$content" ]; then
        warn "No SCAP content found under /usr/share/xml/scap/ssg/content; install ssg-{debian,ubuntu,rhel}."
        return 0
    fi

    log "Running OpenSCAP STIG profile against $content"
    oscap xccdf eval \
        --profile xccdf_org.ssgproject.content_profile_stig \
        --results    "$RESULTS_DIR/openscap_stig_results.xml" \
        --report     "$RESULTS_DIR/openscap_stig_report.html" \
        --oval-results \
        "$content" || warn "oscap returned non-zero (see report)."
    log "OpenSCAP report: $RESULTS_DIR/openscap_stig_report.html"
}

# === Heuristic NIST/ICD/STIG smoke checks (legacy quick-look) ===

check_nist_800_53() {
    log "[heuristic] NIST SP 800-53 smoke checks..."
    local failed=0 total=0

    inc() { total=$((total + 1)); }
    inc; getent passwd aegis_agent >/dev/null && getent group aegis >/dev/null \
        && pass "AC-2: service accounts present" || { fail "AC-2"; failed=$((failed + 1)); }

    inc; systemctl is-active --quiet auditd \
        && pass "AU-2: auditd active" || { fail "AU-2"; failed=$((failed + 1)); }

    inc; [ -f /etc/hispanshield/policies/security.conf ] \
        && pass "CM-6: security policy file" || { fail "CM-6"; failed=$((failed + 1)); }

    inc; (command -v nft >/dev/null 2>&1 || command -v iptables >/dev/null 2>&1) \
        && pass "SC-7: firewall available" || { fail "SC-7"; failed=$((failed + 1)); }

    inc; [ -s /etc/hispanshield/secrets/sentinel.token ] \
        && [ "$(stat -c '%a' /etc/hispanshield/secrets/sentinel.token 2>/dev/null)" = "400" ] \
        && pass "IA-5: sentinel token present and 400" \
        || { fail "IA-5: token missing or wrong perms"; failed=$((failed + 1)); }

    inc; sysctl -n kernel.kptr_restrict 2>/dev/null | grep -q '^[12]$' \
        && pass "SI-7: kernel.kptr_restrict hardened" || { fail "SI-7"; failed=$((failed + 1)); }

    inc; sysctl -n kernel.dmesg_restrict 2>/dev/null | grep -q '^1$' \
        && pass "SI-7: kernel.dmesg_restrict on" || { fail "SI-7"; failed=$((failed + 1)); }

    inc; sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null | grep -q '^1$' \
        && pass "SC-39: unprivileged_bpf_disabled" || { fail "SC-39"; failed=$((failed + 1)); }

    printf '{ "standard": "NIST-SP-800-53", "passed": %d, "failed": %d, "total": %d }\n' \
        "$((total - failed))" "$failed" "$total" \
        > "$RESULTS_DIR/nist_800_53.json"
    log "NIST: $((total - failed))/$total"
}

check_icd_503() {
    log "[heuristic] ICD 503 checks..."
    local failed=0 total=0
    inc() { total=$((total + 1)); }

    inc; [ -d /etc/secureboot/keys/db ] \
        && pass "ICD 503: Secure Boot db present" || { fail "ICD 503: Secure Boot"; failed=$((failed + 1)); }

    inc; { [ -d /etc/hispanshield/tpm ] || [ -c /dev/tpm0 ]; } \
        && pass "ICD 503: TPM available" || { fail "ICD 503: TPM"; failed=$((failed + 1)); }

    inc; (grep -q '^GRUB_CMDLINE_LINUX.*fips=1' /etc/default/grub 2>/dev/null \
            || cat /proc/sys/crypto/fips_enabled 2>/dev/null | grep -q '^1$') \
        && pass "ICD 503: FIPS mode" || { fail "ICD 503: FIPS"; failed=$((failed + 1)); }

    printf '{ "standard": "ICD-503", "passed": %d, "failed": %d, "total": %d }\n' \
        "$((total - failed))" "$failed" "$total" \
        > "$RESULTS_DIR/icd_503.json"
    log "ICD 503: $((total - failed))/$total"
}

check_stigs() {
    log "[heuristic] DISA STIG smoke checks..."
    local failed=0 total=0
    inc() { total=$((total + 1)); }

    inc; grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config 2>/dev/null \
        && pass "STIG: SSH password auth disabled" || { fail "STIG: SSH"; failed=$((failed + 1)); }

    inc; grep -q '^PermitRootLogin no' /etc/ssh/sshd_config 2>/dev/null \
        && pass "STIG: SSH PermitRootLogin no" || { fail "STIG: SSH root"; failed=$((failed + 1)); }

    inc
    local shadow_perms
    shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null || echo 0)
    [ "$shadow_perms" = "640" ] || [ "$shadow_perms" = "000" ] || [ "$shadow_perms" = "600" ] \
        && pass "STIG: /etc/shadow perms ($shadow_perms)" || { fail "STIG: shadow ($shadow_perms)"; failed=$((failed + 1)); }

    inc; [ -f /etc/audit/rules.d/immutable-audit.rules ] \
        && pass "STIG: immutable audit rules installed" || { fail "STIG: audit rules"; failed=$((failed + 1)); }

    inc; auditctl -s 2>/dev/null | grep -q 'enabled 2' \
        && pass "STIG: auditctl in enforce-immutable mode" || { fail "STIG: auditctl mode"; failed=$((failed + 1)); }

    printf '{ "standard": "DISA-STIG", "passed": %d, "failed": %d, "total": %d }\n' \
        "$((total - failed))" "$failed" "$total" \
        > "$RESULTS_DIR/stig.json"
    log "STIG: $((total - failed))/$total"
}

generate_common_criteria_docs() {
    log "Refreshing Common Criteria evaluation status..."
    cat > "$RESULTS_DIR/common_criteria_eal4+.md" << 'DOCS'
# HispanShield OS — Common Criteria EAL4+ Status

Status: Self-assessment. **Not** an external evaluator certification.

## TOE
HispanShield OS LLmSecurity (Sentinel + Gatekeeper).

## SFRs (claimed)
- FDP_ACF.1, FDP_IFC.1 (Bell-La Padula MLS via aegis-mls.te)
- FIA_AFL.1, FIA_UAU.5 (PAM stack: pam_pkcs11 + pam_u2f, no password fallback)
- FMT_MSA.1, FPT_RCV.3, FPT_RPL.1
- FTP_ITC.1: Tauri↔Sentinel currently bearer-token only; **mTLS pending Fase 4**.

## Open gaps for true EAL4+
- Independent evaluation lab not yet engaged.
- mTLS pending; no PKI ceremony.
- fs-verity baseline must be re-measured after every release.
DOCS
}

main() {
    log "HispanShield Compliance Scan — $(date -Iseconds)"
    run_openscap_stig
    check_nist_800_53
    check_icd_503
    check_stigs
    generate_common_criteria_docs
    log "Done. Results in: $RESULTS_DIR"
}

main "$@"
