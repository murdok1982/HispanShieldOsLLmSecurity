#!/usr/bin/env bash
# FINAL BUILD SCRIPT - HispanShield OS Military Grade
# Run this in WSL2 or Debian/Ubuntu host

set -euo pipefail

echo "==============================================================="
echo "HispanShield OS LLmSecurity - FINAL MILITARY BUILD"
echo "Producto Estatal-Militar - Todas las mejoras implementadas"
echo "==============================================================="

# 1. Verify Rust installation
if ! command -v cargo &> /dev/null; then
    echo "[+] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# 2. Compile Rust core components (Military Grade - Memory Safe)
echo "[+] Compiling Rust core components..."
cd /mnt/c/Users/USUARIO/Desktop/proyectos/ActualizacionProyectos/HispanShieldOsLLmSecurity/core/rust

cargo build --release
if [ $? -eq 0 ]; then
    echo "[+] Rust compilation SUCCESSFUL"
    ls -la target/release/aegis-*
else
    echo "[!] Rust compilation FAILED"
    exit 1
fi

# 3. Build Standard ISO (8GB+ RAM)
echo "[+] Building standard ISO..."
cd /mnt/c/Users/USUARIO/Desktop/proyectos/ActualizacionProyectos/HispanShieldOsLLmSecurity
sudo ./build_iso.sh

# 4. Build Edge Tactical ISO (4GB RAM)
echo "[+] Building Edge Tactical ISO..."
sudo ./build_iso_edge.sh

# 5. Run Security & Compliance Test Suite
echo "[+] Running test suite..."
sudo bash core/test_suite.sh

# 6. Generate SBOM
echo "[+] Generating SBOM..."
sudo bash core/compliance/generate_sbom.sh

# 7. Sign all binaries with state PGP key
echo "[+] Signing binaries with state PGP key..."
if gpg --list-keys "HispanShield State" &> /dev/null; then
    gpg --detach-sign --armor -u "HispanShield State" \
        target/release/aegis-sentinel
    gpg --detach-sign --armor -u "HispanShield State" \
        target/release/aegis-gatekeeper
    echo "[+] Binaries signed successfully"
else
    echo "[!] State PGP key not found - signing skipped"
fi

echo "==============================================================="
echo "BUILD COMPLETE - HispanShield OS Military Grade"
echo "ISOs generated:"
echo "  - HispanShieldOS-LLmSecurity-Release1.iso (Standard)"
echo "  - HispanShieldOS-Edge-Tactical.iso (4GB RAM)"
echo "==============================================================="
echo "VERIFICATION:"
echo "  1. Test ISO in VM: boot with Secure Boot enabled"
echo "  2. Verify TPM 2.0: systemctl status aegis-llm-runtime"
echo "  3. Test MFA: Login requires hardware token"
echo "  4. Test MLS: selinux status (enforcing, mls policy)"
echo "  5. Test offensive tools: nmap_scan (requires MFA)"
echo "  6. Verify audit: journalctl -u aegis-agent-core"
echo "==============================================================="
