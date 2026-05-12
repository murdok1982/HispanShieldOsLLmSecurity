# 🗺️ HispanShield OS - Roadmap Público y Hitos (GitHub Projects)

Este documento sirve como base para el tablero de GitHub Projects del repositorio, definiendo hitos medibles, fechas estimadas y criterios de aceptación claros para cada fase del desarrollo hacia un producto validado.

## Fase 1: Consolidación de Core y Observabilidad
**Fecha Estimada:** Q3 2026
**Estado:** 🚧 En curso

### Hitos Medibles
- **Implementación completa de eBPF:** Reemplazo definitivo del stub actual por hooks reales en syscalls (`execve`, `ptrace`, `bpf`).
- **Validación de Anti-Tamper:** Pruebas de campo de los 4 sensores attestables y ajuste de tolerancias de falsos positivos.

### Criterios de Aceptación
- [ ] Los logs de eBPF se envían correctamente a Sentinel Engine en formato JSON sin pérdida de eventos bajo carga de 10k EPS.
- [ ] El script `self_destruct.sh` es capaz de activarse en un entorno de pruebas ante la manipulación física simulada sin afectar entornos no armados.

---

## Fase 2: Certificación y Contención Ofensiva
**Fecha Estimada:** Q4 2026
**Estado:** 📅 Planificado

### Hitos Medibles
- **MicroVM Isolation:** Migración de la ejecución de herramientas ofensivas a Firecracker/gVisor en lugar del sandbox actual basado solo en AppArmor.
- **TPM Key Sealing Real:** Implementar sellado y desellado de claves LUKS asociado a PCRs específicos del proceso de Secure Boot.

### Criterios de Aceptación
- [ ] Las herramientas ofensivas invocadas por el gatekeeper se ejecutan en su propia MicroVM con interfaces de red virtuales efímeras.
- [ ] El sistema rechaza el arranque si el estado de los PCRs del TPM no coincide con la firma autorizada del kernel y el bootloader.

---

## Fase 3: Integración de Guardrails y PQC
**Fecha Estimada:** Q1 2027
**Estado:** 📅 Planificado

### Hitos Medibles
- **Criptografía Post-Cuántica (PQC):** Implementación de algoritmos Kyber/Dilithium para las firmas de binarios y comunicaciones mTLS.
- **NeMo Guardrails:** Integración del framework NVIDIA NeMo Guardrails para garantizar un control semántico avanzado sobre las salidas del LLM.

### Criterios de Aceptación
- [ ] Toda la comunicación del daemon utiliza certificados PQC generados y validados.
- [ ] El pipeline de QA del LLM (usando `test_alignment.py`) aprueba el 100% de las pruebas contra jailbreaks avanzados documentados gracias a NeMo.
