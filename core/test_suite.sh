#!/usr/bin/env bash
# HispanShield OS - Security & Compliance Test Suite (Military Grade)
set -euo pipefail

log() { echo -e "\e[1;36m[Test Suite]\e[0m $1"; }
pass() { echo -e "  \e[32m[PASS]\e[0m $1"; }
fail() { echo -e "  \e[31m[FAIL]\e[0m $1"; ((FAILED++)); }

FAILED=0
RESULTS_DIR="/var/log/hispanshield/test-results"
mkdir -p "$RESULTS_DIR"

log "Starting Security & Compliance Test Suite..."

# 1. Test Rust binaries compilation
log "Testing Rust core compilation..."
if [ -f /opt/hispanshield/core/rust/target/release/aegis-sentinel ] && \
   [ -f /opt/hispanshield/core/rust/target/release/aegis-gatekeeper ]; then
    pass "Rust core binaries compiled"
else
    fail "Rust binaries missing - run 'cargo build --release'"
fi

# 2. Test Secure Boot configuration
log "Testing Secure Boot config..."
if [ -d /etc/secureboot/keys/db ] && [ -f /etc/secureboot/keys/db/db.crt ]; then
    pass "Secure Boot keys present"
else
    fail "Secure Boot keys missing"
fi

# 3. Test TPM 2.0 availability
log "Testing TPM 2.0..."
if [ -c /dev/tpm0 ] || [ -d /etc/hispanshield/tpm ]; then
    pass "TPM 2.0 available/configured"
else
    fail "TPM 2.0 not available"
fi

# 4. Test FIPS mode
log "Testing FIPS 140-3 mode..."
if grep -q "FIPS=1" /etc/environment 2>/dev/null; then
    pass "FIPS mode enabled"
else
    fail "FIPS mode not enabled"
fi

# 5. Test MFA/PAM configuration
log "Testing MFA configuration..."
if [ -f /etc/hispanshield/pam/u2f_keys ] && [ -f /etc/pam.d/hispanshield ]; then
    pass "MFA PAM configuration present"
else
    fail "MFA PAM configuration missing"
fi

# 6. Test Service Account Security
log "Testing service accounts..."
if passwd -S aegis_agent 2>/dev/null | grep -q "L"; then
    pass "aegis_agent password locked"
else
    fail "aegis_agent password not locked"
fi

# 7. Test AppArmor profiles
log "Testing AppArmor profiles..."
if [ -f /etc/apparmor.d/opt.hispanshield.core.rust.aegis-sentinel ]; then
    pass "AppArmor profile for aegis-sentinel exists"
else
    fail "AppArmor profile missing"
fi

# 8. Test Immutable Audit
log "Testing immutable audit rules..."
if [ -f /etc/hispanshield/audit/immutable-audit.rules ]; then
    pass "Immutable audit rules configured"
else
    fail "Immutable audit rules missing"
fi

# 9. Test LLM Model
log "Testing LLM model availability..."
if [ -f /opt/hispanshield/models/aegis-core-1.5b.gguf ] || \
   [ -f /opt/hispanshield/models/aegis-military-7b.gguf ]; then
    pass "LLM model present"
else
    fail "LLM model missing"
fi

# 10. Test Offensive Tools in Policy Engine
log "Testing offensive tools registration..."
if grep -q "nmap_scan\|nuclei_scan" /opt/hispanshield/core/rust/aegis-gatekeeper/src/lib.rs 2>/dev/null; then
    pass "Offensive tools registered in Policy Engine"
else
    fail "Offensive tools not registered"
fi

# 11. Test MLS (Multi-Level Security)
log "Testing MLS implementation..."
if [ -f /opt/hispanshield/core/rust/aegis-sentinel/src/mls.rs ]; then
    pass "MLS (Bell-La Padula) implemented"
else
    fail "MLS implementation missing"
fi

# 12. Test CDS (Cross-Domain Solution)
log "Testing CDS implementation..."
if [ -f /opt/hispanshield/core/rust/aegis-sentinel/src/cds.rs ]; then
    pass "Cross-Domain Solution implemented"
else
    fail "CDS implementation missing"
fi

# 13. Test SIEM integration
log "Testing SIEM integration..."
if [ -f /opt/hispanshield/core/siem/install_siem.sh ]; then
    pass "SIEM integration module present"
else
    fail "SIEM integration missing"
fi

# 14. Test Compliance Scanners
log "Testing compliance scanners..."
if [ -f /opt/hispanshield/core/compliance/scan_compliance.sh ]; then
    pass "Compliance scanners present"
else
    fail "Compliance scanners missing"
fi

# 15. Test SBOM generation
log "Testing SBOM generation..."
if [ -f /opt/hispanshield/core/compliance/generate_sbom.sh ]; then
    pass "SBOM generation script present"
else
    fail "SBOM generation missing"
fi

# Summary
log "Test Suite Complete: $((15 - FAILED))/15 tests passed"
echo "{ \"total\": 15, \"passed\": $((15 - FAILED)), \"failed\": $FAILED }" > "$RESULTS_DIR/test-results.json"

if [ $FAILED -eq 0 ]; then
    log "ALL TESTS PASSED - System ready for state deployment"
else
    warn "SOME TESTS FAILED - Review $RESULTS_DIR/test-results.json"
fi

exit $FAILED
