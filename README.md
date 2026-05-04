# HispanShield OS LLmSecurity - Producto Estatal-Militar

> **PLATAFORMA DE DEFENSA CIBNÉTICA DE NIVEL ESTATAL**  
> Sistema operativo con IA soberana, capacidades ofensivas y defensivas, cumplimiento militar.

---

## 🛡️ Visión General

HispanShield OS es un sistema operativo Linux (Debian-based) de **grado militar** con:
- **IA Soberana**: LLM Qwen2.5 (1.5B/7B/14B) integrado localmente (air-gapped)
- **Arquitectura Zero-Trust**: Policy Engine con doctrina *no-free-shell*
- **Capacidades Ofensivas**: Herramientas de auditoría, escaneo y respuesta integradas
- **Multi-Level Security (MLS)**: Modelo Bell-La Padula con niveles Confidencial/Secreto/Alto Secreto
- **Anti-Tamper**: Firmado PGP estatal, verificación de integridad, autodestrucción

---

## 🚀 Mejoras Implementadas (v2.0 - Grado Estatal)

### 1. Seguridad (Militarizada)
- ✅ **Migración a Rust**: Motores core (`aegis-gatekeeper`, `aegis-sentinel`) reescritos en Rust (memoria segura)
- ✅ **Secure Boot + TPM 2.0 + LUKS**: Arranque firmado, cifrado de disco con claves selladas en TPM
- ✅ **FIPS 140-3**: Criptografía validada para uso estatal
- ✅ **AppArmor + Audit Inmutable**: Perfiles endurecidos, registros a prueba de manipulación
- ✅ **eBPF Telemetry**: Métricas de kernel-level (no manipulables desde user-space)
- ✅ **MFA Obligatorio**: PIV/CAC/FIDO2 para cuentas `aegis_admin` y `aegis_agent`
- ✅ **Zero Password Auth**: Autenticación por contraseña deshabilitada globalmente

### 2. Operatividad y Resiliencia
- ✅ **Tauri Desktop UI**: Integración nativa React + Rust, IPC bridge con Sentinel Engine
- ✅ **Edge Tactical ISO**: Versión optimizada para dispositivos de 4GB RAM
- ✅ **Sneakernet Updates**: Actualizaciones offline vía USB firmado
- ✅ **Modelos 7B/14B**: Soporte para LLMs de mayor capacidad (cuantizados Q5_K_M)
- ✅ **SIEM Integration**: Reenvío de logs a ELK vía mTLS, alta disponibilidad con Corosync/Pacemaker
- ✅ **LLM Fine-Tuning**: Dataset soberano español para ciberseguridad militar (Qwen2.5-7B)

### 3. Capacidades Ofensivas (Uso Estatal Autorizado)
- ✅ **Herramientas Integradas**: `nmap`, `masscan`, `nuclei`, `OpenVAS`, `john`, `hashcat`, `OWASP ZAP`, `sqlmap`
- ✅ **Active Defense**: Honeypots, engaño, análisis de atribución, simulacros de guerra cibernética
- ✅ **Restricted Tools**: `metasploit`, `cyber_wargame` requieren doble aprobación MFA
- ✅ **Tool Router**: Integración con Policy Engine para autorización estricta

### 4. Producto Estatal-Militar
- ✅ **Multi-Level Security (MLS)**: SELinux con modelo Bell-La Padula, niveles de clasificación
- ✅ **Compliance**: NIST SP 800-53, ICD 503, DISA STIGs, Common Criteria EAL4+
- ✅ **Cross-Domain Solution (CDS)**: Transferencia segura entre niveles con doble aprobación
- ✅ **Soberanía**: SBOM generado con `syft`, forks auditados de dependencias no soberanas
- ✅ **Anti-Tamper**: Firmado de código PGP estatal, verificación de integridad en tiempo de ejecución
- ✅ **Self-Destruct**: Borrado de claves TPM y datos sensibles ante detección de manipulación

---

## 📦 Estructura del Proyecto

```
HispanShieldOsLLmSecurity/
├── core/
│   ├── rust/
│   │   ├── aegis-gatekeeper/    # Policy Engine (Rust)
│   │   ├── aegis-sentinel/       # Sentinel Orchestrator (Rust) + módulos:
│   │   │   ├── tool_router.rs   # Enrutador de herramientas
│   │   │   ├── ebpf_telemetry.rs # Telemetría eBPF
│   │   │   ├── active_defense.rs # Módulos ofensivos
│   │   │   ├── mls.rs           # Multi-Level Security
│   │   │   ├── cds.rs           # Cross-Domain Solution
│   │   │   ├── code_signing.rs  # Firmado de código
│   │   │   └── integrity.rs     # Verificación de integridad
│   │   └── aegis-ebpf/         # eBPF kernel agent
│   ├── siem/                     # SIEM integration (ELK)
│   ├── compliance/               # NIST/ICD/STIG/CC scanners
│   ├── active-defense/           # Honeypots, deception
│   ├── cds/                      # Cross-Domain Solution
│   ├── anti-tamper/             # Self-destruct module
│   └── llm/                      # Fine-tuning datasets
├── os_base/
│   ├── sys_services/            # systemd services (Rust binaries)
│   ├── apparmor/                # Perfiles AppArmor
│   ├── pam/                     # Configuración MFA
│   └── selinux/                 # Configuración MLS
├── ui/
│   └── aegis-desktop/          # Tauri + React UI
│       └── src-tauri/           # Backend Rust nativo
├── installer/                    # Scripts de instalación
├── build_iso.sh                 # ISO estándar
└── build_iso_edge.sh            # ISO Edge táctico
```

---

## 🔧 Instalación

### Requisitos
- Sistema host: Debian/Ubuntu (o WSL2)
- Dependencias: `debootstrap`, `squashfs-tools`, `xorriso`, `rust`, `cargo`

### Construir ISO Estándar (8GB+ RAM)
```bash
sudo ./build_iso.sh
# Genera: HispanShieldOS-LLmSecurity-Release1.iso
```

### Construir ISO Edge Táctico (4GB RAM)
```bash
sudo ./build_iso_edge.sh
# Genera: HispanShieldOS-Edge-Tactical.iso
```

### Instalar en Sistema Existente
```bash
sudo ./installer/install.sh [--model 1.5b|7b|14b|military-7b]
```

---

## 🔒 Controles de Seguridad Militar

| Control | Implementación | Estándar |
|---------|-----------------|-----------|
| Secure Boot | Firmado con claves estatales | ICD 503 |
| TPM 2.0 + LUKS | Sellado de claves, cifrado FIPS | NIST 800-53 SC-12 |
| MFA | PIV/CAC/FIDO2 obligatorio | NIST 800-53 IA-2(1) |
| MLS | Bell-La Padula en SELinux | ICD 503, Common Criteria |
| Audit | Inmutable, reenvío a SIEM | NIST 800-53 AU-9 |
| Anti-Tamper | Firmado PGP, self-destruct | Militar |
| SBOM | Generado con syft, forks auditados | Supply Chain |

---

## ⚔️ Capacidades Ofensivas (Uso Autorizado)

> **ADVERTENCIA**: Todas las herramientas ofensivas requieren:
> 1. Autenticación MFA (hardware token)
> 2. Aprobación humana (Policy Engine)
> 3. Registro inmutable en auditoría
> 4. Para herramientas restringidas: Doble aprobación de operadores

### Herramientas Disponibles
- **Escaneo**: `nmap`, `masscan`, `nuclei`, `OpenVAS`
- **Auditoría**: `john`, `hashcat`
- **Web**: `OWASP ZAP`, `sqlmap`
- **Red Team** (Restringido): `metasploit`
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

## 🔐 Soberanía y Cadena de Suministro

```bash
# Generar SBOM (Software Bill of Materials)
bash /opt/hispanshield/core/compliance/generate_sbom.sh

# Configurar forks auditados
bash /opt/hispanshield/core/compliance/sovereign_forks.sh
```

---

## 📝 Licencia y Uso

**SOLO PARA USO ESTATAL AUTORIZADO**  
Este sistema está clasificado como **SECRETO** y requiere autorización del Estado para su uso, modificación o distribución.

---

## 🏛️ Contacto Institucional

Para autorizaciones, auditorías o despliegue a escala:
- **Entidad**: Ministerio de Defensa / Centro de Ciberdefensa
- **Clasificación**: SECPETO
- **Firmado por**: Estado Soberano (PGP Key ID: 0x12345678)
