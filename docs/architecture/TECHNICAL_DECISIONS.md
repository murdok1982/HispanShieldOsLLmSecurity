# Technical Decisions and Tech Stack Rationale

Este documento justifica la elecciÃ³n de tecnologÃ­as para HispanShield OS LLmSecurity pensando en mantenibilidad, consumo mÃ­nimo de recursos, seguridad ofensiva/defensiva y viabilidad comercial.

## 1. Sistema Base
**ElecciÃ³n:** Debian Minimal (o debootstap) modificado.
**JustificaciÃ³n:** 
- Altamente estable, ecosistema de paquetes maduro (`apt`).
- Permite construir distribuciones comerciales derivadas sÃ³lidas.
- Altamente compatible con AppArmor (perfiles de nÃºcleo).

## 2. Orquestador / Policy Engine
**ElecciÃ³n:** Rust (con integraciones asÃ­ncronas vÃ­a `tokio`).
**JustificaciÃ³n:**
- *Memory Safety:* PrevenciÃ³n nativa contra buffer overflows y use-after-free, mitigando riesgos si el motor del agente recibe entradas manipuladas.
- *Performance:* Consumo bajÃ­simo de RAM al manejar miles de conexiones o monitorear el bus del sistema constantemente.
- El Policy Engine debe estar aislado y ser infalible (rÃ¡pido en evaluaciÃ³n, nulo en fallos de ejecuciÃ³n).

## 3. IntegraciÃ³n LLM Local
**ElecciÃ³n:** `llama.cpp` corriendo como Systemd Service.
**JustificaciÃ³n:**
- Inferencia optimizada en C/C++ directa al hardware (CPU, soporte cuDNN / Metal).
- Permite el uso de GGUF altamente cuantizados (Ej. un Qwen 2.5 1.5B Q5_K_M ocupa apenas 1.1GB de VRAM/RAM).
- Expone un Web Server de API compatible con OpenAI para un desacople muy limpio entre el motor del Agente y la Inteligencia Generativa.

## 4. UI / UX Premium Desktop
**ElecciÃ³n:** Tauri v2 (Backend Node/Rust, Frontend React/Next.js con TailwindCSS y Framer Motion).
**JustificaciÃ³n:**
- Resulta en binarios diminutos en comparaciÃ³n con Electron, esencial para un OS de bajo consumo.
- EstÃ©tica y performance equivalentes a aplicaciones nativas de macOS.
- Excelente conectividad directa y segura (IPC estricto) entre el framework Frontend y el Backend en Rust del Sistema.

## 5. Endurecimiento e IPC
**ElecciÃ³n:** Unix Domain Sockets con control de credenciales (`SO_PEERCRED`), ademÃ¡s de AppArmor y `nftables`.
**JustificaciÃ³n:**
- El Agente corre como usuario `aegis_agent`. Las herramientas crÃ­ticas las ejecuta un wrapper bajo `root`. La Ãºnica conexiÃ³n entre ambos es IPC sobre Sockets validados.
- Impide completamente que procesos maliciosos en user-space se inyecten o hablen con el motor de IA para elevar privilegios.
