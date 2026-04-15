<p align="center">
  <img src="https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge&logo=linux" alt="OS">
  <img src="https://img.shields.io/badge/Security-Zero%20Trust-red?style=for-the-badge&logo=security" alt="Security">
  <img src="https://img.shields.io/badge/AI-Native%20LLM-orange?style=for-the-badge&logo=openai" alt="AI">
  <img src="https://img.shields.io/badge/UI-Tauri%20%2B%20React-cyan?style=for-the-badge&logo=react" alt="UI">
</p>

# 🛡️ HispanShield OS LLmSecurity

**HispanShield OS LLmSecurity** es un sistema operativo premium basado en Linux, diseñado desde cero con una mentalidad **Zero-Trust** y orquestado localmente por inteligencia artificial autónoma (modelos nativos *LLM* integrados en el sistema).

Diseñado con una estética *macOS-inspired* fluida, este sistema reemplaza los frágiles *scripts* tradicionales y la supervisión humana intensiva por un **Agente Inteligente Sentinel** vigilante, residente en las capas más profundas el núcleo del sistema operativo.

---

## 🧠 Mapa Mental de Características

```mermaid
mindmap
  root((HispanShield OS))
    Seguridad Zero-Trust
      Aislamiento Telemetría
      Router "No-Free-Shell"
      Policy Gatekeeper
      Gestor de Secretos
    Motor IA Autónomo
      Air-Gapped Local LLM
      Sentinel Engine
      Qwen2.5 / Gemma2B
    UI Premium
      Desktop estilo macOS
      Aegis Security Center
      Control NL Spotlight
    Core
      Kernel Ring-0
      Gestor de Snapshots
```

---

## 🔒 Mecanismos "Zero-Trust" y de Seguridad

El núcleo de **HispanShield** se estructura alrededor de 4 pilares inquebrantables de seguridad:

1. **🛡️ Aislamiento de Telemetría (*AegisEye*)**: El observador lee métricas directamente en modo `ring-0` (Kernel) en tiempo real. Esto elimina el envenenamiento de estado mediante ejecución maliciosa. El agente siente y monitoriza el pulso real de la máquina.
2. **🧠 Motor LLM Local (*Qwen2.5-1.5B/Gemma2B*)**: Integrado de fábrica. Ofrece capacidades generativas ricas con apenas ~1GB de consumo de RAM y funciona bajo **aislamiento total de red local (Air-gapped)**, imposibilitando cualquier posible fuga de información (Exfiltration).
3. **🚫 Restricción "No-Free-Shell"**: HispanShield carece intencionalmente de la clásica e insegura terminal accesible a la IA general. El motor LLM jamás ejecuta instrucciones directas de `bash`. Cada acción es enrutada mediante firmas estrictamente tipadas.
4. **🛑 Guardián de Políticas (*Policy Engine Gatekeeper*)**: Todo intento de cambio de sistema es denegado por defecto. Acciones drásticas a nivel de *kernel* o archivos invocan alertas interactivas a través de *Aegis Security Center*, forzando confirmación matemática e interactiva por el dueño (UID 1000).

---

## ⚙️ Arquitectura del Sistema

```mermaid
graph TD
  subgraph UI ["🖥️ Interfaz Premium (Tauri + React)"]
    A[Aegis Security Center]
    B[Desktop & Dock]
    C[Spotlight AI Widget]
  end
  
  subgraph Security Core ["🛡️ Capa de Seguridad (Python/Rust)"]
    D[🧠 Sentinel Engine AI]
    E[🛑 Policy Gatekeeper]
    F[👁️ AegisEye Telemetry]
    G[🔑 Secrets Manager]
  end
  
  subgraph OS ["🐧 Sistema Base"]
    H[Kernel Ring-0]
    I[Recursos del Sistema]
  end

  A <-->|Live Logs & Autorizaciones| E
  C -->|Comandos Naturales| D
  D -->|Firmas Estrictas JSON| E
  E -->|Ejecución Restringida| I
  F -->|Lectura Analítica| H
  F -->|Flujo de Datos| D
```

---

## 🛡️ Flujo de Aprobación de Acciones (Gatekeeper)

A continuación se expone cómo el **Policy Gatekeeper** intercepta acciones potencialmente peligrosas derivadas de peticiones de usuario:

```mermaid
sequenceDiagram
  autonumber
  actor User as Usuario (UID 1000)
  participant AI as Sentinel Engine (LLM)
  participant Gate as Policy Gatekeeper
  participant Eye as AegisEye
  participant Sys as OS Kernel

  User->>AI: Petición Natural (Ej. "Cierra procesos sospechosos")
  Eye->>AI: Contexto del Sistema Ring-0
  AI->>Gate: Solicitud Firmada (Tipeado Estricto)
  Gate->>Gate: Evaluación de Riesgo y Políticas
  
  alt Riesgo Crítico / Acceso Profundo
      Gate->>User: Modales UI (Confirmación Requerida)
      User-->>Gate: Aprobación Criptográfica
  end
  
  Gate->>Sys: Ejecuta la acción securizada
  Sys-->>Gate: Retorno de estado
  Gate-->>AI: Feedback
  AI-->>User: Éxito reportado al UI
```

---

## 🖥️ Experiencia Premium (UI)

La interacción hacia *HispanShield OS* no recae en oscuras CLI, sino en una plataforma de tecnología web compilada como binarios nativos (**Tauri + React/Vite**).

- **🌌 Escritorio, Dock y Barra Superior**: Animaciones cinéticas suaves (`framer-motion`), diseño Glassmorphism impulsado con librerías modernas como Tailwind CSS y temas dinámicos de OS.
- **🛡️ Aegis Security Center**: Exquisito panel forense de auditoría que lista el log interactivo minuto a minuto: rastrea cada acción y autorización mediada por el *Sentinel Engine*.
- **🔎 Spotlight del Agente (Widget Inteligente)**: Barra desplegable global, siempre atenta, lista para interceptar intenciones naturales (NL) de configuración o protección.

---

## 💿 Instalación y Despliegue

Existen dos vías recomendadas y securizadas de implantación:

### 1️⃣ Método 1: Bare-Metal (Instalación ISO Nativa)
Ruta principal para la máxima seguridad por hardware.
1. Compila o descarga el paquete ISO `HispanShieldOS-LLmSecurity-Release1.iso` *(Usa los scripts provistos en Debian/Ubuntu como `build_iso.sh`)*.
2. Formatea el pendrive / medio extraíble *(mín. 8 GB)* usando utilidades confiables (Rufus, BalenaEtcher).
3. Arranca con prioridad USB desde la BIOS/UEFI.
4. **Verificación Póstuma**: HispanShield verificará hashes precalculados internamente. El LLM se descargará solo tras un Handshake certificado mediante llave SHA256.

### 2️⃣ Método 2: Subsistema Inyectado (Servidor Linux Huésped)
Si deseas implementar las protecciones de *HispanShield* sobre distros base (Preferente Debian 12):
1. Clona o mueve este repositorio a entornos locales seguros (Ej: `~/hispanshieldos/`).
2. Inicializa las políticas de aislamiento e inyección del núcleo:
   ```bash
   sudo ./installer/install.sh
   ```
3. El instalador segmentará dependencias, atará *sub-usuarios* cautivos y creará los *sockets IPC* unix requeridos. Al culminar, la *UI* de escritorio estará disponible para empoderar al SO.
