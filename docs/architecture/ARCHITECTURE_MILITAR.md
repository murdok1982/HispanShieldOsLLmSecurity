# Architecture Documentation - HispanShield OS LLmSecurity (Military Grade)

## System Overview

HispanShield OS is a state-military security operating system featuring:
- **Rust-based core engines** (memory-safe, no segfaults)
- **Local LLM** (Qwen2.5, air-gapped, fine-tuned for military cybersecurity)
- **Zero-Trust architecture** with no-free-shell doctrine
- **Multi-Level Security** (Bell-La Padula model)
- **Offensive capabilities** (authorized state use only)

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    HISPANTSHIELD OS (Military)             │
├─────────────────────────────────────────────────────────────┤
│  UI Layer (Tauri + React)                                 │
│  ├─ SecurityPanel.tsx (Telemetry, Audit Log)              │
│  ├─ AIWidget.tsx (Sentinel Agent Chat)                     │
│  └─ IPC Bridge → Rust Backend                             │
├─────────────────────────────────────────────────────────────┤
│  Core Engines (Rust)                                      │
│  ├─ aegis-sentinel (Orchestrator)                        │
│  │   ├─ tool_router.rs (Strict JSON routing)              │
│  │   ├─ active_defense.rs (Honeypots, Wargames)          │
│  │   ├─ mls.rs (Bell-La Padula MLS)                     │
│  │   ├─ cds.rs (Cross-Domain Solution)                    │
│  │   ├─ code_signing.rs (State PGP signing)              │
│  │   └─ integrity.rs (Runtime checks, Anti-Tamper)      │
│  └─ aegis-gatekeeper (Policy Engine)                     │
│      └─ Allowlist + Human Approval + MFA Enforcement      │
├─────────────────────────────────────────────────────────────┤
│  LLM Runtime (llama.cpp)                                 │
│  └─ Qwen2.5-1.5B/7B/14B (Fine-tuned military)          │
├─────────────────────────────────────────────────────────────┤
│  eBPF Telemetry (Kernel-Level)                            │
│  └─ aegis-ebpf (Cannot be spoofed by user-space)        │
├─────────────────────────────────────────────────────────────┤
│  OS Hardening (Debian Base)                              │
│  ├─ Secure Boot + TPM 2.0 + LUKS (FIPS 140-3)         │
│  ├─ AppArmor Profiles (Strict sandboxing)                 │
│  ├─ MFA (PIV/CAC/FIDO2) - No password auth             │
│  ├─ Immutable Audit (aegis, SIEM forward)                │
│  └─ Self-Destruct (TPM wipe on tamper)                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Modules

### 1. Policy Engine (`aegis-gatekeeper`)
- **Allowlist Tools**: Only pre-approved tools can execute
- **Human Approval**: `requires_human: true` tools need UI confirmation
- **Dual MFA**: Restricted military tools need two operators
- **Offensive Tools**: `nmap`, `nuclei`, `metasploit`, etc. (authorized use only)

### 2. Sentinel Orchestrator (`aegis-sentinel`)
- **FSM Design**: Finite State Machine, not infinite loop
- **LLM Integration**: OpenAI-compatible API to llama.cpp
- **Clean/Ditry Context**: Separates system state from user input
- **eBPF Telemetry**: Kernel-level metrics (CPU, RAM, network)

### 3. Multi-Level Security (`mls.rs`)
- **Security Levels**: Confidencial (100), Secreto (200), Alto Secreto (300)
- **No-Read-Up**: Cannot read objects above clearance
- **No-Write-Down**: Cannot write objects below clearance
- **SELinux MLS**: Enforced via SELinux policy

### 4. Cross-Domain Solution (`cds.rs`)
- **Transfer Requests**: Cross-classification data movement
- **Dual Approval**: Two operators must approve
- **Guards**: Content scanning, malware detection, classification check
- **Audit**: All transfers logged immutably

### 5. Active Defense (`active_defense.rs`)
- **Honeypots**: Deception environments for attackers
- **Attribution**: TTP analysis, APT identification
- **War Games**: Cyber simulation exercises
- **Deception**: Fake data, phantom credentials, misleading topology

---

## Security Controls

| Control | Implementation | Standard |
|---------|-----------------|-----------|
| Secure Boot | State-signed keys (db) | ICD 503 |
| TPM 2.0 | LUKS key sealing | NIST 800-53 SC-12 |
| FIPS 140-3 | OpenSSL FIPS mode | FIPS 140-3 |
| MFA | PAM U2F/PKCS11 | NIST 800-53 IA-2(1) |
| MLS | Bell-La Padula (SELinux) | ICD 503, CC EAL4+ |
| Audit | Immutable, SIEM forward | NIST 800-53 AU-9 |
| Anti-Tamper | PGP signing, integrity checks | Military |
| Self-Destruct | TPM wipe, disk header overwrite | Military |

---

## Build & Deployment

### Standard ISO (8GB+ RAM)
```bash
sudo ./build_iso.sh
# Output: HispanShieldOS-LLmSecurity-Release1.iso
```

### Edge Tactical ISO (4GB RAM)
```bash
sudo ./build_iso_edge.sh
# Output: HispanShieldOS-Edge-Tactical.iso
```

### Model Selection
```bash
sudo ./installer/install.sh --size 1.5b   # Edge (4GB)
sudo ./installer/install.sh --size 7b      # Standard (8GB)
sudo ./installer/install.sh --size 14b     # Server (16GB)
sudo ./installer/install.sh --size military-7b  # Fine-tuned military
```

---

## Compliance

### Automated Scanners
- **NIST SP 800-53**: `core/compliance/scan_compliance.sh`
- **ICD 503**: Intelligence Community Directive 503
- **DISA STIG**: Security Technical Implementation Guides
- **Common Criteria**: EAL4+ documentation in `compliance/`

### SBOM (Software Bill of Materials)
```bash
bash core/compliance/generate_sbom.sh
# Outputs: 
# - aegis-gatekeeper-sbom.json
# - aegis-sentinel-sbom.json
# - python-sbom.json
# - sovereignty-audit.json
```

---

## State Authorization

**CLASSIFICATION**: SECRETO  
**AUTHORIZED USE ONLY**: Requires state approval  
**SIGNED**: Estado Soberano (PGP: 0x12345678)  

Any unauthorized use, reproduction, or modification is strictly prohibited.
