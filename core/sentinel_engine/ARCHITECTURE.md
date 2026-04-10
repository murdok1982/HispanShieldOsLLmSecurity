# Sentinel Engine Architecture

El *Sentinel Engine* es el "Cerebro Seguro" de HispanShield OS LLmSecurity. Evoluciona la idea de un agente analÃ­tico pero reemplazando la fe ciega por validaciÃ³n estricta y observaciÃ³n cruzada. Su diseÃ±o es completamente original para evitar deuda tÃ©cnica y arquitecturas dÃ©biles de proyectos experimentales.

## Arquitectura de MÃ³dulos (Separation of Concerns)

### 1. El Observador: *AegisEye*
Un demonio local independiente que continuamente monitorea el sistema.
- Registra uso e interrupciones de sistema.
- Censa el I/O y conexiones netstat/ss de la red.
- Conoce los servicios de systemd actuales e historial de caÃ­das recientes.
**PropÃ³sito:** Cuando el usuario pide hacer algo, el contexto de fondo no procede del usuario, sino de los datos criptogrÃ¡ficamente seguros y reales de *AegisEye*. Esto mata el vector de contexto envenenado.

### 2. El Orquestador
Es el hilo principal del Sentinel. En lugar de tener un bucle infinito ("Agent Loop"), usa MÃ¡quinas de Estados Finitos (FSM).
- Recibe Request â­¢ Obtiene AegisEye State â­¢ Consolida System Prompt Oculto â­¢ Solicita Plan a LLM.
- **Diferenciador:** Mantiene dos hilos de contexto separados en la memoria; uno para los datos seguros y reglas (nunca modificables), y otro canal temporal "sucio" (dirty channel) para lo que provee el exterior.

### 3. El Tool Router (Contratos de Herramientas Estrictos)
Transforma y serializa las intenciones.
Si el Agente decide que necesita listar procesos, invoca de manera tipada `{ "tool": "process.list", "args": { "filter_user": "all" } }`.
El Tool Router no ejecuta directamente la Ã³rden OS; la encapsula en un protocolo RPC interno y la lanza al Policy Engine.

### 4. El Policy Engine
El guardiÃ¡n (Gatekeeper). Escrito exclusivamente en un lenguaje *memory-safe* y ejecutado independientemente.
Valida mediante matrices de RBAC (Role-Based Access Control) y Reglas por Defecto (Deny).

## Flujo de Trabajo TÃ­pico

1. **Usuario:** "El equipo va muy lento, cierra lo que estÃ© fallando."
2. **Orquestador:** Consulta *AegisEye*. AegisEye reporta carga de disco alta por proceso "X".
3. **LLM Runtime (Inferencia Externa Local):** Determina: `{"thought": "El proceso X es anÃ³malo y consume excesivo IO", "action": "KillProcess", "pid": "XXXX"}`.
4. **Tool Router:** Extrae y valida la solicitud JSON. No existen shells disponibles, sÃ³lo la herramienta `KillProcess`.
5. **Policy Engine:** EvalÃºa matriz "KillProcess sobre aplicaciÃ³n local". *Aprobado automÃ¡ticamente* debido al bajo riesgo y aislamiento.
6. **Ejecutor CrÃ­tico:** Mata el PID utilizando syscall nativa (no usando `bash kill -9`).
7. **Motor de Logs Inmutables:** Graba la operaciÃ³n en `aegis_audit.db`.
8. **Orquestador (Mensaje UI):** Notifica al usuario interactivo "He terminado el proceso X en background por uso anÃ³malo".
