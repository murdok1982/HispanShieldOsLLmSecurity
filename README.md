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

La auditoría de Mayo 2026 identificó vulnerabilidades críticas y brechas de capacidad. El ciclo de corrección de Mayo 2026 cierra las vulnerabilidades de mayor prioridad. Esta sección refleja el estado post-corrección.

### ✅ Implementado y Validado

**Correcciones críticas (BLOQUE 1):**
- LLM local soberano (Qwen2.5 + llama.cpp) con Bind a 127.0.0.1 y --api-key vía LoadCredential.
- **Gatekeeper Rust — validación de parámetros** (`validate_parameters`): cada herramienta tiene esquema de claves permitidas, longitud máxima, bloqueo de metacaracteres de shell y validación de patrón.
- **Gatekeeper Rust — canal dirty/clean** (`ChannelType`): herramientas de alto impacto solo pueden invocarse desde canal Clean (sensores internos firmados).
- **Gatekeeper Rust — guard de segundo orden ai_query**: detecta y bloquea payloads que embeben llamadas a herramientas dentro de un prompt de `ai_query` (prompt injection de segundo orden).
- Audit inmutable (auditd -e 2) con reglas append-only.
- PAM PIV/CAC + FIDO2 (pam_u2f + pam_pkcs11, password auth deshabilitado).
- **SIEM: Elasticsearch/Kibana/Logstash con bind a 127.0.0.1** — ya no escucha en 0.0.0.0. mTLS con `xpack.security.http.ssl.client_authentication=required`.

**Nuevas capacidades (BLOQUE 2):**
- **Self-destruct: crypto-erasure para SSD/NVMe** — `cryptsetup luksKillSlot` + `nvme format --ses=1` + `hdparm --security-erase` + `blkdiscard` antes del DoD 5220.22-M (solo HDD mecánicos con ROTA=1).
- **Self-destruct: cold-boot RAM mitigation** — `kexec` a kernel de borrado + fallback `mlock`+`os.urandom` Python3.
- **IMA/EVM — integridad de binarios en tiempo de ejecución** (`os_base/ima/`): política IMA PCR[10], appraisal `imasig`, clave EVM RSA-4096 sellada en TPM NV.
- **Fine-tuning con verificación de provenance** (`core/llm/finetune.sh`): GPG del dataset, SHA-256 vs TPM NV:0x1500010, análisis estático de 8 patrones backdoor/jailbreak, sellado hash GGUF en TPM NV:0x1500011.
- **Suricata NIDS integrado con SIEM** (`core/siem/suricata-compose.yml`): port scan, DNS tunnelling, ICMP tunnel, LLM server isolation, Metasploit/CS beacon, honeypot access. Pipeline Logstash mTLS.
- **MISP local air-gap** (`core/threat-intel/local_misp_setup.sh`): MISP en Docker con `--network none`, feeds GPG-cifrados desde USB.
- **Criptografía post-cuántica** (`core/rust/aegis-pqc/`): KEM híbrido X25519+Kyber768 HKDF-SHA3-256 (FIPS 203), firma Dilithium3 (FIPS 204), AEAD AES-256-GCM.
- **Firecracker MicroVM sandbox** (`core/sandbox/firecracker_runner.sh`): MicroVM efímera por tool, rootfs read-only + overlay descartable, TAP con iptables default-deny, vsock I/O, cleanup en EXIT trap.

**Nuevas capacidades (Mayo 2026 — segunda iteración):**
- **eBPF Fase 2 — aya TracePoint + KProbe** (`core/rust/aegis-ebpf/`): programa C BPF con TracePoints en `sys_enter_execve` y `sys_enter_prctl`, KProbe en `do_init_module`, PerfEventArray, mapa `pid_blocklist`. Loader userspace Rust vía `aya` (feature flag `--features ebpf`). Fallback automático a proc-scanner (Fase 0) si no hay BPF object compilado.
- **NeMo Guardrails runtime** (`core/nemo-guardrails/`): clase `HispanShieldGuardrails` con `check_input`, `check_output` y `process` async. Intenta cargar NeMo en runtime; fallback a regex compilados que espejean todos los flows Colang de `rails.co`. Decisiones HMAC-SHA256 a `/var/log/hispanshield/guardrails.log`.
- **Guardrails Integration** (`core/sentinel_engine/orchestrator/guardrails_integration.py`): corrutinas `apply_input_rails` y `apply_output_rails` con wrappers síncronos. Cada decisión firmada con HMAC-SHA256 (`HISPANSHIELD_AUDIT_KEY`).
- **GRC Engine — Compliance automático** (`core/compliance/grc_engine.py`): 18 controles automatizados (8 NIST 800-53, 5 DISA STIG, 5 HispanShield custom). Genera informes JSON + texto con tabla resumen y puntuación. CLI con `--format`, `--output`, `--framework`. Integrado en `scan_compliance.sh`.
- **Spectre C2 — canal operador Tor/I2P** (`core/c2/spectre_c2.sh`): Tor v3 hidden service + I2P backup channel, mTLS con certs CA/server/operator, auth token en TPM NV:0x1500020 + dual-MFA gate 300s TTL, audit HMAC-SHA256 en cada evento. Direcciones `.onion` nunca a stdout (OPSEC).
- **Offensive-tools rootfs builder** (`core/sandbox/build_offensive_rootfs.sh`): debootstrap Debian Bookworm con repositorio Kali verificado GPG, instalación de herramientas de red/web/post-exploitation, ext4 sellado read-only, hash en TPM NV:0x1500031, firma GPG opcional.
- **Vsock dispatcher** (`core/sandbox/vsock-dispatcher.sh`): corre dentro del MicroVM, escucha en VSOCK port 9999, allowlist de herramientas, rechazo de metacaracteres shell, timeout máximo 300s, log en `/var/log/aegis-vsock.log`.
- **vmlinux downloader** (`core/sandbox/vm-rootfs/vmlinux-download.sh`): instrucciones de build reproducible desde fuente + verificación GPG de Linus + sellado TPM NV:0x1500032.

### ⚠️ Implementado pero No Validado Externamente

- Anti-tamper con sensores attestables (requiere auditoría de los triggers en hardware real).
- TPM key sealing (sellado por fingerprint en NV; sellado por PCR en `tpm2_create` pendiente de entorno con TPM físico).
- SELinux MLS Bell-LaPadula (PoC limitado, solo carga en Fedora/RHEL).

### ❌ No Implementado (Requiere Hardware Específico)

- Hardware RoT (OpenTitan) — requiere silicon dedicado.
- Compilación BPF del objeto `aegis-ebpf.bpf.o` — requiere clang + kernel headers en el host de build.

---

## Estructura del Proyecto

```
HispanShieldOsLLmSecurity/
├── core/
│   ├── policy/tools.yaml             # fuente única de verdad de la allowlist
│   ├── rust/
│   │   ├── aegis-gatekeeper/         # Policy Engine: validación de parámetros + canal dirty/clean + guard ai_query
│   │   ├── aegis-sentinel/           # Orchestrator + CDS + integrity + tool_router
│   │   ├── aegis-ebpf/               # Fase 0 proc-scanner activo; Fase 2 aya eBPF (--features ebpf)
│   │   │   └── src/aegis-ebpf.bpf.c  # Programa C BPF: TracePoint execve/prctl + KProbe do_init_module
│   │   ├── aegis-pqc/                # KEM híbrido Kyber768+X25519 + Dilithium3 + AES-256-GCM (FIPS 203/204)
│   │   └── deny.toml                 # cargo-deny: licencias, bans, advisories
│   ├── sentinel_engine/              # dev harness Python (NO enforcement)
│   │   └── orchestrator/
│   │       └── guardrails_integration.py  # Guardrails coroutines con audit HMAC-SHA256
│   ├── siem/
│   │   ├── docker-compose.yml        # ELK con puertos bind 127.0.0.1 + mTLS
│   │   ├── suricata-compose.yml      # Suricata NIDS + pipeline Logstash
│   │   └── suricata/rules/           # Reglas personalizadas HispanShield (SID 9000001-9000050)
│   ├── sandbox/
│   │   ├── firecracker_runner.sh     # MicroVM efímera por tool con TAP aislado y vsock I/O
│   │   ├── build_offensive_rootfs.sh # Builder ext4 offensive-tools con Debian+Kali GPG-verified
│   │   ├── vsock-dispatcher.sh       # Dispatcher vsock en-VM con allowlist y metachar-rejection
│   │   └── vm-rootfs/
│   │       └── vmlinux-download.sh   # Descargador/builder vmlinux para Firecracker
│   ├── c2/
│   │   ├── spectre_c2.sh             # Canal operador Tor v3 + I2P + mTLS + auth TPM + audit HMAC
│   │   ├── tor/torrc.template        # Tor v3 hidden service: HiddenServiceVersion 3, SafeLogging, bandwidth
│   │   └── i2p/tunnels.conf.template # I2P server tunnel
│   ├── nemo-guardrails/
│   │   ├── config/config.yml         # Configuración NeMo Guardrails
│   │   ├── config/rails.co           # Colang flows: jailbreak, exfiltración, PII, clasificado, ...
│   │   ├── guardrails_engine.py      # HispanShieldGuardrails: NeMo + fallback regex HMAC-logged
│   │   └── requirements.txt          # nemoguardrails>=0.9.0
│   ├── compliance/
│   │   ├── grc_engine.py             # 18 controles: NIST 800-53 + DISA STIG + HispanShield custom
│   │   ├── scan_compliance.sh        # Orquestador con llamada al GRC engine
│   │   ├── generate_sbom.sh          # SBOM con syft
│   │   └── sovereign_forks.sh        # Mirror auditado de dependencias
│   ├── threat-intel/
│   │   └── local_misp_setup.sh       # MISP air-gap: --network none, feeds USB GPG-firmados
│   ├── anti-tamper/                  # self-destruct: crypto-erasure SSD/NVMe + cold-boot RAM wipe
│   └── llm/                          # fine-tuning: GPG + TPM NV + análisis backdoor + hash sellado
├── os_base/
│   ├── ima/
│   │   ├── ima-policy                # Política IMA/EVM: medición PCR[10] + appraisal imasig
│   │   └── setup_ima_evm.sh          # Generación clave EVM RSA-4096, sellado TPM, firma binarios
│   ├── sys_services/                 # units systemd endurecidas
│   ├── apparmor/                     # perfiles AppArmor
│   ├── pam/                          # PIV/CAC + FIDO2
│   ├── selinux/                      # módulo MLS PoC
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
| Tool gating | Allowlist + validación de parámetros + canal dirty/clean + guard ai_query | doctrina propia |
| Anti-tamper | 4 sensores attestables + crypto-erasure SSD/NVMe + cold-boot RAM mitigation | doctrina propia |
| Integridad de binarios | IMA/EVM: medición SHA-256 en PCR[10] + appraisal `imasig` | NIST SP 800-155 |
| Telemetría kernel | aegis-ebpf Fase 0 (proc) + Fase 2 eBPF (TracePoint+KProbe) via aya | MITRE T1059 |
| Guardrails LLM | NeMo Guardrails Colang + fallback regex; audit HMAC-SHA256 por decisión | OWASP LLM Top 10 |
| NIDS local | Suricata con reglas HispanShield (port scan, DNS tunnel, LLM isolation) | MITRE T1048 |
| Inteligencia de amenazas | MISP air-gap con feeds USB GPG-firmados, sin dependencias cloud | MISP / STIX/TAXII |
| Criptografía PQ | Kyber768 + Dilithium3 + X25519 híbrido + AES-256-GCM (FIPS 203/204) | NIST FIPS 203/204 |
| Sandbox MicroVM | Firecracker VM efímera por tool, TAP aislado, default-deny, vsock dispatcher | Principio mínimo privilegio |
| Provenance LLM | GPG + TPM NV hash + análisis backdoor en dataset + hash modelo post-train | NIST AI RMF |
| Compliance GRC | 18 controles automatizados: NIST 800-53 + DISA STIG + HispanShield custom | NIST 800-53 / DISA STIG |
| Canal operador | Spectre C2: Tor v3 + I2P + mTLS + auth TPM NV + dual-MFA + audit HMAC | OPSEC doctrina propia |

---

## Capacidades Ofensivas (uso autorizado)

Toda invocación requiere:

1. Autenticación MFA hardware-backed.
2. Aprobación humana (Policy Engine Rust).
3. Registro inmutable con HMAC.
4. Para herramientas restringidas: doble aprobación (CDS) con separación temporal.
5. Ejecución en MicroVM Firecracker efímera (rootfs read-only, TAP aislado, vsock I/O).

Herramientas disponibles dentro del sandbox:
- **Red:** `nmap`, `masscan`, `socat`, `netcat`, `tcpdump`, `tshark`
- **Web:** `nikto`, `gobuster`, `sqlmap`
- **Credenciales:** `hydra`, `john`, `hashcat`, `crackmapexec`
- **Post-explotación:** `impacket`, `responder`, `metasploit-framework`
- **Análisis:** `strace`, `gdb`, `python3`

---

## Compliance

```bash
sudo python3 /opt/hispanshield/core/compliance/grc_engine.py \
    --format text --output /var/log/hispanshield/compliance/grc_$(date +%Y%m%d).txt
# O a través del orquestador completo:
sudo bash /opt/hispanshield/core/compliance/scan_compliance.sh
```

Marcos cubiertos automáticamente: NIST 800-53, DISA STIG, HispanShield custom (18 controles).

---

## Soberanía y Cadena de Suministro

```bash
bash /opt/hispanshield/core/compliance/generate_sbom.sh   # SBOM con syft
bash /opt/hispanshield/core/compliance/sovereign_forks.sh # mirror auditado
```

---

## eBPF Fase 2 — Compilar y activar

```bash
# 1. Compilar el programa C BPF
clang -O2 -g -target bpf \
    -I/usr/include/x86_64-linux-gnu \
    -c core/rust/aegis-ebpf/src/aegis-ebpf.bpf.c \
    -o /opt/hispanshield/bin/aegis-ebpf.bpf.o

# 2. Compilar el loader Rust con feature flag
cd core/rust
cargo build --release --features ebpf -p aegis-ebpf

# 3. El daemon detecta automáticamente el objeto BPF y activa Fase 2
/opt/hispanshield/bin/aegis-ebpf
```

---

## Canal Operador (Spectre C2)

```bash
# Provisionar token en TPM (una vez por despliegue)
sudo ./core/c2/spectre_c2.sh provision-token

# Iniciar canal (requiere dual-MFA completado y token en env)
sudo HISPANSHIELD_C2_AUTH_TOKEN=<token> ./core/c2/spectre_c2.sh start

# El canal queda disponible vía Tor v3 (dirección en audit log únicamente)
# I2P como canal de backup
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
declarativas (CNE — Computer Network Exploitation) se ejecutan **dentro de
MicroVMs Firecracker aisladas** bajo control del Policy Engine. Su exportación
cruzando frontera podría requerir licencia **EAR / Wassenaar**; consulte
asesoría legal antes de cualquier distribución, mirror público o transferencia
internacional.

Las claves PGP referenciadas en el repositorio son de desarrollo. No se
reclama firma de autoridad estatal hasta que el proceso de auditoría externa
termine y la entidad responsable sustituya la confianza por su propia raíz.

---

## CENTRO DE COMUNICACIONES Y REPORTES OFICIALES

**NIVEL DE ACCESO:** AUTORIZADO | **DESTINATARIO:** COMANDANCIA DE DESARROLLO (gustavolobatoclara@gmail.com)

A través del siguiente portal de comunicaciones, el personal autorizado puede emitir reportes de incidencias, fallas críticas en despliegue (compilación) o solicitudes de mejoras estratégicas.

<details>
<summary><b>REPORTAR QUEJA O INCIDENCIA DISCIPLINARIA / OPERATIVA</b></summary>
<br>
Para tramitar una queja sobre el funcionamiento, estructura o contenido del sistema, envíe un mensaje a <b>gustavolobatoclara@gmail.com</b> siguiendo este protocolo:
<ol>
  <li><b>Asunto:</b> [QUEJA] - Nombre del Sistema - Breve descripción.</li>
  <li><b>Cuerpo del mensaje:</b> Detallar claramente la incidencia, impacto operativo y, si es posible, la evidencia (capturas o logs).</li>
  <li><b>Prioridad:</b> Indicar si es de atención inmediata o diferida.</li>
</ol>
</details>

<details>
<summary><b>REPORTE DE PROBLEMAS DE COMPILACIÓN O DESPLIEGUE</b></summary>
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
<summary><b>SUGERENCIAS O SOLICITUDES DE DESARROLLO</b></summary>
<br>
Para proponer nuevas capacidades tácticas, módulos de inteligencia o mejoras de arquitectura, envíe su solicitud a <b>gustavolobatoclara@gmail.com</b>:
<ol>
  <li><b>Asunto:</b> [PROPUESTA] - Mejora o Nuevo Módulo.</li>
  <li><b>Objetivo Táctico:</b> ¿Qué problema resuelve o qué ventaja proporciona esta nueva característica?</li>
  <li><b>Viabilidad:</b> (Opcional) Posible enfoque técnico o herramientas recomendadas para su implementación.</li>
</ol>
</details>
