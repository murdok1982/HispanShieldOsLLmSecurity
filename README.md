# HispanShield OS LLmSecurity

**HispanShield OS LLmSecurity** es un sistema operativo premium basado en Linux, diseñado desde cero con una mentalidad **Zero-Trust** y orquestado localmente por inteligencia artificial autónoma (modelos nativos *LLM* integrados en el sistema).

Diseñado con una estética *macOS-inspired* fluida, este sistema reemplaza los frágiles *scripts* tradicionales y la supervisión humana intensiva, por un Agente Inteligente vigilante residente en las capas más profundas el núcleo del sistema operativo.

---

## 🔒 Capacidades y Principios "Zero-Trust"

1. **Aislamiento de Telemetría (*AegisEye*)**: El observador lee métricas directamente en modo ring-0 (Kernel) en tiempo real. Esto elimina el envenenamiento de estado mediante ejecución maliciosa. El agente "siente" realmente el pulso real de la máquina.
2. **Motor LLM Local (*Qwen2.5-1.5B/Gemma2B*)**: Integrado de fábrica. Ofrece capacidades generativas ultra ricas con apenas ~1GB de consumo de memoria y con aislamiento total de red local (Air-gapped) — imposibilitando cualquier fuga de información (Exfiltration).
3. **Restricción "No-Free-Shell"**: HispanShield carece intencionalmente de la clásica e insegura terminal de IA general. El motor LLM jamás toca `bash`. Su razonamiento es derivado a través de un ruteador (Router tipado) que exige firmas strictas para cada acción.
4. **Guardián Interactivo (Policy Engine Gatekeeper)**: Todo cambio del sistema es bloqueado por defecto. Acciones legítimas como aislar un proceso en fondo se autorizan matemáticamente; cambios de núcleo invocan modales del panel *Aegis Security Center* que requieren intervención forzosa de confirmación por el dueño (UID 1000).

---

## 🖥 Experiencia Premium (UI)

La ventana hacia *HispanShield OS* está construida con tecnología web compilada a formato binario embebido compacto (Tauri + React).
- **El Escritorio y Dock**: Presenta animaciones suaves, dock de inicio inferior y barra de menú superior al estilo mac.
- **Aegis Security Center**: Exquisito panel Glassmorphism de auditoría forense que lista minuto a minuto (live log) la traza de autorizaciones/bloqueos gestionados contra la IA.
- **Widget de Agent (Spotlight Inteligente)**: Siempre listo para interactuar mediante comandos naturales (NL).

---

## 💿 Proceso de Instalación

Existen dos vías principales de implantación.

### Método 1: Bare-Metal (Instalación desde imagen oficial .iso)
Esta es la ruta completa para desplegar HispanShield en un hardware primario.
1. Compila o descarga el archivo `HispanShieldOS-LLmSecurity-Release1.iso`. *(Nótese: para compilar manualmente requerirás una VM Debian/Ubuntu con las herramientas del script `build_iso.sh`).*
2. Usa **Rufus** o **BalenaEtcher** para flashear la `.iso` en una memoria USB de mínimo 8 GB.
3. Arranca el PC configurando en la BIOS el medio extraíble.  
4. El Instalador realizará un Check de Sumas Seguras (Hash precalculados) del firmware del sistema para certificar tu copia comercial. Tras arrancar y crear a tu usuario, descargarás de forma segura y validada (mediante SHA256) el LLM.

### Método 2: Subsistema Empotrado o Server Remoto
Si cuentas con un entorno base Linux (Debian 12):
1. Copia y ubica este proyecto completo en un directorio como `~/hispanshieldos/`.
2. Otorga privilegios plenos e inicializa la inyección del núcleo:
   ```bash
   sudo ./installer/install.sh
   ```
3. El script creará sub-usuarios cautivos en el SO huésped y lanzará los servicios de backend para operar mediante IPC seguro y sockets unix. Finalmente, instala las dependencias npm requeridas para compilar Tauri (`ui/aegis-desktop`) de cara a iniciar el *Desktop UI*.
