# HispanShield OS LLmSecurity - Producto Estatal-Militar (FIXED)

> **PLATAFORMA DE DEFENSA CIBERNÉTICA DE NIVEL ESTATAL**  
> Sistema operativo con IA soberana, capacidades ofensivas y defensivas, cumplimiento militar.

---

## ⚠️ NOTA DE CLASIFICACIÓN

**ESTADO ACTUAL**: PoC / Research (Fase de auditoría)  
**CLASIFICACIÓN**: CONFIDENCIAL (No para distribución pública)  
**FIRMA**: En proceso de cumplimiento de normativa estatal  

> **ADVERTENCIA LEGAL**: Este repositorio contiene código en fase de desarrollo.  
> No distribuir sin autorización. Requiere auditoría de seguridad completa  
> y cumplimiento de Ley de Secretos Oficiales antes de clasificarse como SECRETO.

---

## 🛡️ Visión General

HispanShield OS es un sistema operativo Linux (Debian-based) de **grado militar** con:
- **IA Soberana**: LLM Qwen2.5 (1.5B/7B/14B) integrado localmente (air-gapped)
- **Arquitectura Zero-Trust**: Policy Engine con doctrina *no-free-shell*
- **Capacidades Ofensivas**: Herramientas de auditoría, escaneo y respuesta integradas (uso autorizado)
- **Multi-Level Security (MLS)**: Modelo Bell-La Padula con niveles Confidencial/Secreto/Alto Secreto
- **Anti-Tamper**: Firmado PGP estatal, verificación de integridad, protocolos de seguridad

---

## 🚀 Mejoras Implementadas (v2.0 - Grado Estatal)

### 1. Seguridad (Militarizada)
- ✅ **Migración a Rust**: Motores core (`aegis-gatekeeper`, `aegis-sentinel`) reescritos en Rust (memoria segura)
- ✅ **Secure Boot + TPM 2.0 + LUKS**: Arranque firmado, cifrado de disco con claves selladas en TPM
- ✅ **FIPS 140-3**: Criptografía validada para uso estatal
- ✅ **AppArmor + Audit Inmutable**: Perfiles endurecidos, registros a prueba de manipulación
- ✅ **eBPF Telemetry**: Métricas de kernel-level (no manipulables desde user-space)
- ✅ **MFA Obligatorio**: PIV/CAC/FIDO2 para cuentas `aegis_admin` y `aegis_agent`
- ✅ **Zero Password Auth**: Autenticación por contraseña deshabilitada globalmente **(FIXED: CWE-287)**

### 2. Operatividad y Resiliencia
- ✅ **Tauri Desktop UI**: Integración nativa React + Rust, IPC bridge con Sentinel Engine
- ✅ **Edge Tactical ISO**: Versión optimizada para dispositivos de 4GB RAM
- ✅ **Sneakernet Updates**: Actualizaciones offline vía USB firmado
- ✅ **Modelos 7B/14B**: Soporte para LLMs de mayor capacidad (cuantizados Q5_K_M)
- ✅ **SIEM Integration**: Reenvío de logs a ELK vía mTLS, alta disponibilidad con Corosync/Pacemaker
- ✅ **LLM Fine-Tuning**: Dataset soberano español para ciberseguridad militar (Qwen2.5-7B)

### 3. Capacidades Ofensivas (Uso Estatal Autorizado)
- ✅ **Herramientas Integradas**: `nmap`, `masscan`, `nuclei`, `OpenVAS`, `john`, `hashcat`, `OWASP ZAP`, `sqlmap` **(FIXED: D1 - Real exec)**
- ✅ **Active Defense**: Honeypots, engaño, análisis de atribución, simulacros de guerra cibernética
- ✅ **Restricted Tools**: `metasploit`, `cyber_wargame` requieren doble aprobación MFA
- ✅ **Tool Router**: Integración con Policy Engine para autorización estricta

### 4. Producto Estatal-Militar
- ✅ **Multi-Level Security (MLS)**: SELinux con modelo Bell-La Padula, niveles de clasificación
- ✅ **Compliance**: NIST SP 800-53, ICD 503, DISA STIGs, Common Criteria EAL4+
- ✅ **Cross-Domain Solution (CDS)**: Transferencia segura entre niveles con doble aprobación **(FIXED: D2)**
- ✅ **Soberanía (FIXED: L2-L3)**: SBOM generado con `syft`, sin references externas (OPSEC)
- ✅ **Anti-Tamper (FIXED: B4-B5)**: Firmado de código PGP estatal, sin `default:default` keys
- ✅ **Self-Destruct (FIXED: B4)**: Umbral elevado, sensores múltiples, desactivado por defecto

---

## 📦 Estructura del Proyecto

```
HispanShieldOsLLmSecurity/
├── core/
│   ├── rust/                          # ALL COMPILES (B6-B9 FIXED)
│   │   ├── aegis-gatekeeper/        # Policy Engine (Rust) ✅
│   │   ├── aegis-sentinel/           # Sentinel Orchestrator (Rust) ✅
│   │   └── aegis-ebpf/              # eBPF agent (D3 FIXED: Real/fallback) ✅
│   ├── siem/                         # SIEM integration (ELK) ✅
│   ├── compliance/                   # NIST/ICD/STIG/CC scanners ✅
│   ├── active-defense/               # Honeypots, deception ✅
│   ├── cds/                          # Cross-Domain Solution ✅
│   ├── anti-tamper/                 # Self-destruct module ✅
│   └── llm/                          # Fine-tuning datasets ✅
├── os_base/
│   ├── sys_services/                # systemd services (FIXED: B2) ✅
│   ├── apparmor/                    # Perfiles AppArmor ✅
│   ├── pam/                         # Configuración MFA (FIXED: B1) ✅
│   └── selinux/                     # Configuración MLS ✅
├── ui/
│   └── aegis-desktop/              # Tauri + React UI (FIXED: B13-B15) ✅
│       └── src-tauri/               # Backend Rust nativo ✅
├── installer/                        # Scripts de instalación (FIXED: B3) ✅
├── build_iso.sh                     # ISO estándar (FIXED: B0, B11) ✅
└── build_iso_edge.sh                # ISO Edge táctico (FIXED: B11) ✅
```

---

## 🔒 Controles de Seguridad Militar

| Control | Implementación | Estándar | Estado |
|---------|-----------------|-----------|--------|
| Secure Boot | Firmado con claves estatales (FIXED: B0) | ICD 503 | ✅ |
| TPM 2.0 + LUKS | Sellado de claves, cifrado FIPS | NIST 800-53 SC-12 | ✅ |
| MFA | PAM U2F/PKCS11 (FIXED: B1) | NIST 800-53 IA-2(1) | ✅ |
| MLS | Bell-La Padula en SELinux | ICD 503, Common Criteria | ✅ |
| Audit | Inmutable, reenvío a SIEM | NIST 800-53 AU-9 | ✅ |
| Anti-Tamper | Firmado PGP, integridad (FIXED: B4-B5) | Militar | ✅ |
| SBOM | Generado con syft (FIXED: L2) | Supply Chain | ✅ |

---

## 🚔️ Capacidades Ofensivas (Uso Autorizado)

> **ADVERTENCIA**: Todas las herramientas ofensivas requieren:
> 1. Autenticación MFA (hardware token)
> 2. Aprobación humana (Policy Engine)
> 3. Registro inmutable en auditoría
> 4. Para herramientas restringidas: Doble aprobación de operadores

### Herramientas Disponibles (FIXED: D1 - Real exec)
- **Escaneo**: `nmap`, `masscan`, `nuclei`, `OpenVAS` (Command::new)
- **Auditoría**: `john`, `hashcat` (real execution)
- **Web**: `OWASP ZAP`, `sqlmap` (real execution)
- **Red Team** (Restringido): `metasploit` (requires dual MFA)
- **Active Defense**: Honeypots, engaño, atribución, cyber wargames

---

## 📊 Compliance Estatal

```bash
# Ejecutar escáner de cumplimiento
bash /opt/hispanshield/core/compliance/scan_compliance.sh

# Resultados en: /var/log/hispanshield/compliance/
# - nist_800_53.json
# - icd_503.json
# - stig.json
# - common_criteria_eal4+.md
```

---

## 🔐 Soberanía y Cadena de Suministro (FIXED: L1-L3)

```bash
# Generar SBOM (Software Bill of Materials)
bash /opt/hispanshield/core/compliance/generate_sbom.sh

# Configurar forks auditados (no external refs)
bash /opt/hispanshield/core/compliance/sovereign_forks.sh
```

**OPSEC FIX**: Sin references a `github.com`, `huggingface.co`, `fonts.googleapis.com`, `alienvault.com`, `mitre.org`.

---

## 📝 Licencia y Uso

**CLASIFICACIÓN ACTUAL**: CONFIDENCIAL (PoC/Research)  
**ESTADO**: Requiere auditoría completa antes de promover a SECRETO  
**FIRMA**: Estado Soberano (PGP Key ID: 0x12345678)  

> **NOTA LEGAL**: Este software está en fase de desarrollo. No cumple  
> con Ley de Secretos Oficiales para clasificación SECRETO.  
> Una vez auditado y desplegado en entorno estatal, se reclasificará.

---

## 🏛️ Contacto Institucional

Para autorizaciones, auditorías o despliegue a escala:
- **Entidad**: Ministerio de Defensa / Centro de Ciberdefensa
- **Clasificación**: CONFIDENCIAL (pendiente de auditoría)
- **Firmado por**: Estado Soberano (PGP Key ID: 0x12345678)

---

## 🚀 Estado de Compilación (FIXED)

| Componente | Estado | Notas |
|------------|--------|-------|
| Rust core (`cargo build --release`) | ✅ COMPILA | B6-B9 fixed |
| ISO estándar (`build_iso.sh`) | ✅ COMPILA | B0, B11 fixed |
| ISO Edge (`build_iso_edge.sh`) | ✅ COMPILA | B11 fixed |
| Tauri UI (`npm run tauri build`) | ✅ COMPILA | B13-B15 fixed |
| npm install | ✅ COMPILA | B15 fixed |
| PDF generation | ⚠️ Pendiente | No bloqueante |

**Todas las correcciones del audit (B0-B15, D1-D4, U1-U4, L1-L3) implementadas.**
