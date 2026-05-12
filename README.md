# HispanShield OS LLmSecurity — PoC / Reference Architecture — Not for Production Deployment

> **Hardened reference architecture** for a Linux endpoint that runs a sovereign LLM
> behind a strict tool-calling gatekeeper. This repository is research-grade work,
> not a production distribution.

---

## NOTA DE CLASIFICACIÓN

**ESTADO ACTUAL:** PoC / Research — auditoría externa en curso.
**CLASIFICACIÓN:** CONFIDENCIAL (no para distribución pública).
**FIRMA:** No firmado por autoridad estatal — claves del repositorio son de desarrollo.

---

## Visión General

HispanShield OS es una arquitectura de referencia (Debian-based) que combina:

- **LLM local** (Qwen2.5 1.5B/7B/14B vía `llama.cpp`) detrás de auth obligatoria y bind a `127.0.0.1`.
- **Gatekeeper Rust** con allowlist estricta, validación anti-shell-metachar y separación dual-MFA para herramientas restringidas.
- **Userland endurecido**: AppArmor, audit inmutable, PAM PIV/CAC + FIDO2, systemd hardening completo, sysctl mínimo.
- **UI Tauri** con clasificación visible, consentimiento explícito y gate anti-tamper.

---

## Estado de implementación

La auditoría de Mayo 2026 detectó overselling significativo. Esta sección clarifica el estado real del sistema para alinear las expectativas con la realidad técnica.

### ✅ Implementado y Validado
- LLM local soberano (Qwen2.5 + llama.cpp) con Bind a 127.0.0.1 y --api-key vía LoadCredential.
- Gatekeeper Rust con allowlist estricta (Command::new sin shell, validación de metacaracteres).
- Audit inmutable (auditd -e 2) con reglas append-only.
- PAM PIV/CAC + FIDO2 (pam_u2f + pam_pkcs11, password auth deshabilitado).
- Systemd hardening completo (ProtectSystem=strict, SystemCallFilter).
- CDS dual-MFA con separación temporal y verificación criptográfica HMAC real.
- UI Tauri con clasificación visible y componentes de consentimiento.

### ⚠️ Implementado pero No Validado Externamente
- Anti-tamper con sensores attestables (Configurado para producción sin dry-run, requiere auditoría de los triggers).
- TPM key sealing (Parcial, uso de cmdline + LUKS, pero sin sellado por PCR específico).
- SELinux MLS Bell-LaPadula (PoC limitado, solo carga en Fedora/RHEL).

### 🚧 En Desarrollo (Roadmap)
- eBPF telemetry kernel-side (Fase 0/Stub reemplazado por hooks reales en syscalls como execve, en desarrollo continuo).
- Compliance Scanners (Scripts actuales no integran con GRC completo, mejoras en cadena de custodia implementadas).

### ❌ No Implementado (Deseado)
- PQC (Kyber/Dilithium) - Solo documentado, sin implementación criptográfica post-cuántica real.
- MicroVM isolation para tools ofensivas - Actualmente usa AppArmor + seccomp, sin sandboxing real tipo Firecracker.
- NeMo Guardrails runtime - No implementado, se usa lógica Rust propia.
- Spectre C2 stack (Tor/I2P) - Esqueleto/setup.
- Hardware RoT (OpenTitan) - Requiere hardware específico.

---

## Estructura del Proyecto

```
HispanShieldOsLLmSecurity/
├── core/
│   ├── policy/tools.yaml             # fuente única de verdad de la allowlist
│   ├── rust/
│   │   ├── aegis-gatekeeper/         # Policy Engine (autoritativo)
│   │   ├── aegis-sentinel/           # Orchestrator + CDS + integrity + tool_router
│   │   ├── aegis-ebpf/               # Fase 0 stub — ver Roadmap
│   │   └── deny.toml                 # cargo-deny: licencias, bans, advisories
│   ├── sentinel_engine/              # dev harness Python (NO enforcement)
│   ├── siem/                         # forwarder ELK mTLS
│   ├── compliance/                   # scanners NIST / ICD / STIG
│   ├── active-defense/               # honeypots y deception (declarativo)
│   ├── cds/                          # Cross-Domain Solution
│   ├── anti-tamper/                  # self-destruct conservador
│   └── llm/                          # datasets de fine-tuning
├── os_base/
│   ├── sys_services/                 # units systemd endurecidas
│   ├── apparmor/                     # perfiles AppArmor
│   ├── pam/                          # PIV/CAC + FIDO2
│   ├── selinux/                      # módulo MLS PoC (ver README adyacente)
│   ├── audit/                        # reglas inmutables + fs-verity
│   └── sysctl/                       # hardening de kernel via sysctl
├── ui/aegis-desktop/                 # Tauri + React (UI clasificada)
├── installer/                        # scripts de instalación
└── .github/workflows/                # gates de CI (clippy, audit, deny, test)
```

---

## Controles de Seguridad — qué está realmente activo

| Control | Implementación | Estándar |
|---|---|---|
| MFA hardware | PAM `pam_u2f` + `pam_pkcs11` (FIDO2 + PIV/CAC) | NIST 800-53 IA-2(1) |
| Audit inmutable | `auditd -e 2` + reglas append-only | NIST 800-53 AU-9 |
| MAC layer | AppArmor en producción + SELinux MLS opcional | DISA STIG |
| Service hardening | systemd: `ProtectSystem=strict`, `CapabilityBoundingSet=`, `SystemCallFilter` | CIS Linux |
| LLM auth | `--api-key` obligatorio, bind 127.0.0.1, token en `LoadCredential` | CWE-942 / CWE-306 |
| Tool gating | Allowlist estricta + dual-MFA en restringidas | doctrina propia |
| Anti-tamper | 4 sensores attestables, dry-run por defecto | doctrina propia |

---

## Capacidades Ofensivas (uso autorizado)

> 🚧 **Estado: Roadmap parcial** — los binarios se invocan vía `Command::new` con
> validación, pero la **sandboxing real (MicroVM)** está en Fase 2. Hoy la
> contención se apoya únicamente en AppArmor + seccomp + UID dedicado.

Toda invocación requiere:

1. Autenticación MFA hardware-backed.
2. Aprobación humana (Policy Engine).
3. Registro inmutable.
4. Para herramientas restringidas: doble aprobación de operadores con separación temporal (CDS).

Herramientas integradas:
- **Escaneo:** `nmap`, `masscan`, `nuclei`, OpenVAS.
- **Auditoría:** `john`, `hashcat`.
- **Web:** OWASP ZAP, sqlmap.
- **Restringido:** `metasploit`, honeypot/deception, atribución, cyber wargames (dual-MFA).

---

## Compliance

> 🚧 **Estado: Roadmap Fase 2** — los scanners son scripts declarativos que
> producen evidencia parcial. NO son una certificación.

```bash
bash /opt/hispanshield/core/compliance/scan_compliance.sh
# Resultados en /var/log/hispanshield/compliance/
```

---

## Soberanía y Cadena de Suministro

```bash
bash /opt/hispanshield/core/compliance/generate_sbom.sh   # SBOM con syft
bash /opt/hispanshield/core/compliance/sovereign_forks.sh # mirror auditado
```

---

## CI / Security gates

`.github/workflows/security.yml` ejecuta en cada push y PR a `main`:

- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --release`
- `cargo audit` (RustSec advisory database)
- `cargo deny check` (licencias permisivas, bans, advisories — config en `core/rust/deny.toml`)

---

## Licencia y Uso

Este código es PoC/Research. No cumple aún con Ley de Secretos Oficiales para
clasificación SECRETO. Una vez auditado y desplegado, se reclasificará.

---

## Disclaimer

Este repositorio es una **arquitectura de referencia y PoC**. **NO debe
desplegarse en hardware civil sin auditoría adicional**. Capacidades ofensivas
declarativas (CNE — Computer Network Exploitation) **NO están implementadas**
en este release y su exportación cruzando frontera podría requerir licencia
**EAR / Wassenaar**; consulte asesoría legal antes de cualquier distribución,
mirror público o transferencia internacional.

Las claves PGP referenciadas en el repositorio son de desarrollo. No se
reclama firma de autoridad estatal hasta que el proceso de auditoría externa
termine y la entidad responsable sustituya la confianza por su propia raíz.

---

## 🎖️ CENTRO DE COMUNICACIONES Y REPORTES OFICIALES
**NIVEL DE ACCESO:** AUTORIZADO | **DESTINATARIO:** COMANDANCIA DE DESARROLLO (gustavolobatoclara@gmail.com)

A través del siguiente portal de comunicaciones, el personal autorizado puede emitir reportes de incidencias, fallas críticas en despliegue (compilación) o solicitudes de mejoras estratégicas. Seleccione la directiva correspondiente para visualizar los protocolos de envío:

<details>
<summary><b>🚨 REPORTAR QUEJA O INCIDENCIA DISCIPLINARIA / OPERATIVA</b></summary>
<br>
Para tramitar una queja sobre el funcionamiento, estructura o contenido del sistema, envíe un mensaje a <b>gustavolobatoclara@gmail.com</b> siguiendo este protocolo:
<ol>
  <li><b>Asunto:</b> [QUEJA] - Nombre del Sistema - Breve descripción.</li>
  <li><b>Cuerpo del mensaje:</b> Detallar claramente la incidencia, impacto operativo y, si es posible, la evidencia (capturas o logs).</li>
  <li><b>Prioridad:</b> Indicar si es de atención inmediata o diferida.</li>
</ol>
</details>

<details>
<summary><b>🛠️ REPORTE DE PROBLEMAS DE COMPILACIÓN O DESPLIEGUE</b></summary>
<br>
Si experimenta fallos durante la fase de compilación o instalación del sistema, reporte a <b>gustavolobatoclara@gmail.com</b> con la siguiente estructura técnica:
<ol>
  <li><b>Asunto:</b> [COMPILACIÓN] - Falla en entorno &lt;Entorno/OS&gt;.</li>
  <li><b>Especificaciones:</b> Sistema Operativo, versión de dependencias y herramientas de compilación utilizadas.</li>
  <li><b>Traza de Error (Logs):</b> Adjunte el log completo de errores proporcionado por la terminal (en formato texto o captura legible).</li>
  <li><b>Pasos de Reproducción:</b> Secuencia exacta de comandos ejecutados antes del fallo crítico.</li>
</ol>
</details>

<details>
<summary><b>💡 SUGERENCIAS O SOLICITUDES DE DESARROLLO</b></summary>
<br>
Para proponer nuevas capacidades tácticas, módulos de inteligencia o mejoras de arquitectura, envíe su solicitud a <b>gustavolobatoclara@gmail.com</b>:
<ol>
  <li><b>Asunto:</b> [PROPUESTA] - Mejora o Nuevo Módulo.</li>
  <li><b>Objetivo Táctico:</b> ¿Qué problema resuelve o qué ventaja proporciona esta nueva característica?</li>
  <li><b>Viabilidad:</b> (Opcional) Posible enfoque técnico o herramientas recomendadas para su implementación.</li>
</ol>
</details>

---
