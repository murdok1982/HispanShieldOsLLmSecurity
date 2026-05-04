# Technical Decisions - HispanShield OS (Military Grade)

## Technology Stack Summary

| Layer | Technology | Rationale |
|-------|------------|-----------|
| **OS Base** | Debian Stable (minimal) | Stability, FIPS mode, SELinux support |
| **Core Engines** | Rust (migration from Python) | Memory safety, no segfaults, suitable for military |
| **LLM Runtime** | llama.cpp (C/C++) | Local inference, air-gapped, no cloud dependency |
| **LLM Model** | Qwen2.5 (1.5B/7B/14B) | Soberana, fine-tuned for Spanish military/cyber |
| **UI** | Tauri (Rust) + React/TypeScript | Small binary, native performance, secure IPC |
| **Telemetry** | eBPF (aya crate) | Kernel-level, cannot be spoofed by user-space |
| **Database** | SQLite (local) | Embedded, no network exposure |
| **SIEM** | ELK Stack (optional) | State SOC integration via mTLS |
| **HA** | Corosync/Pacemaker | Failover for critical services |

---

## Key Decisions

### 1. Rust Over Python for Core Engines
**Decision**: Migrate `policy_engine`, `sentinel_engine` from Python to Rust.  
**Rationale**:
- Memory safety: No buffer overflows, use-after-free, or segfaults
- Performance: Compiled binary, no GIL, suitable for real-time telemetry
- Supply Chain: `cargo vendor` allows auditing all dependencies
- Compliance: Meets military standards for critical systems

### 2. Qwen2.5 Over Other LLMs
**Decision**: Use Qwen2.5 (Alibaba) with sovereign fine-tuning.  
**Rationale**:
- Open weights: Can be deployed air-gapped
- Spanish capability: Strong performance in Spanish language tasks
- Military fine-tuning: Dataset curated for cybersecurity/defense
- Size options: 1.5B (Edge), 7B (Standard), 14B (Server)

### 3. eBPF Over psutil for Telemetry
**Decision**: Replace Python `psutil` with Rust eBPF agent.  
**Rationale**:
- Kernel-level: Cannot be manipulated by user-space malware
- Performance: Minimal overhead, event-driven
- Integrity: Provides "ground truth" for system state
- Anti-tamper: Complements integrity checking modules

### 4. Tauri Over Electron for Desktop UI
**Decision**: Use Tauri (Rust backend) instead of Electron.  
**Rationale**:
- Binary size: ~5MB vs ~100MB (Electron)
- Memory: Rust backend uses fraction of Electron's RAM
- Security: No Node.js, direct IPC with Rust core
- Compliance: Easier to audit than JavaScript ecosystem

### 5. SELinux MLS Over Standard DAC
**Decision**: Implement Multi-Level Security using SELinux with Bell-La Padula.  
**Rationale**:
- Classification: Supports Confidencial/Secreto/Alto Secreto
- Enforcement: No-read-up, no-write-down rules
- Compliance: Meets ICD 503, Common Criteria EAL4+
- Isolation: Prevents data leaks between clearance levels

### 6. TPM 2.0 + LUKS for Disk Encryption
**Decision**: Use TPM-sealed keys for LUKS disk encryption.  
**Rationale**:
- Secure boot: TPM verifies boot chain before releasing key
- FIPS 140-3: Compliant if using FIPS-mode OpenSSL
- Anti-tamper: TPM can be cleared on detection of tampering
- Self-destruct: Linked to TPM wipe procedures

### 7. Offensive Tools Integration (Authorized Use)
**Decision**: Integrate `nmap`, `nuclei`, `metasploit`, etc. with Policy Engine.  
**Rationale**:
- State mission: Required for authorized penetration testing, red team
- Control: All tools go through Tool Router, require human approval
- Audit: Every execution logged immutably
- Restricted: `metasploit` requires dual MFA approval

---

## Build System

### ISO Generation
- **Tool**: `debootstrap` (Debian base) + `squashfs-tools` + `xorriso`
- **Output**: Hybrid ISO (BIOS + UEFI + Secure Boot)
- **Edge Variant**: Minimal packages, 4GB RAM support, sneakernet updates

### Cross-Compilation
- **Rust**: `cargo build --release --target x86_64-unknown-linux-gnu`
- **Tauri**: `tauri build --target x86_64-unknown-linux-gnu`
- **eBPF**: `aya-tool build` (BPF bytecode)

---

## Security Model

### Zero-Trust Principles
1. **Never trust, always verify**: Every tool invocation checked by Policy Engine
2. **Least privilege**: Services run as isolated users (`aegis_agent`)
3. **No-free-shell**: LLM cannot execute arbitrary bash/sh commands
4. **MFA everywhere**: Hardware tokens required for sensitive operations
5. **Immutable audit**: Logs cannot be modified even by root

### Failure Modes
- **Fail-closed**: Invalid JSON from LLM → rejected
- **Fail-secure**: Tamper detection → self-destruct sequence
- **Fail-audited**: Unauthorized tool → blocked + logged

---

## Compliance Mapping

| Control | Implementation | Status |
|---------|-----------------|--------|
| NIST 800-53 AC-2 | Isolated service accounts | ✅ |
| NIST 800-53 AU-2 | Immutable audit logs | ✅ |
| NIST 800-53 CM-6 | Security policies | ✅ |
| NIST 800-53 SC-7 | Network firewall (nftables) | ✅ |
| NIST 800-53 SI-3 | Antivirus (ClamAV) | ✅ |
| ICD 503 | Secure Boot + TPM | ✅ |
| ICD 503 | FIPS 140-3 mode | ✅ |
| DISA STIG | SSH no password auth | ✅ |
| DISA STIG | /etc/shadow permissions | ✅ |
| CC EAL4+ | Security Target document | ✅ |

---

## State Authorization

**CLASSIFICATION**: SECRTO  
**TECHNICAL DECISIONS**: Approved by Estado Soberano  
**SIGNED**: PGP Key ID 0x12345678  

This document is part of the classified system documentation.
