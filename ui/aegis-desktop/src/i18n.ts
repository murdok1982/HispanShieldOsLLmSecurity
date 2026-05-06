import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Locales completos para el bloque FRONTEND del Sprint 3.
// Convención: claves en snake_case, agrupadas por dominio funcional.
const resources = {
  'en-US': {
    translation: {
      // Shell / chrome
      security_center: 'Aegis Security Center',
      brand: 'HispanShield OS LLmSecurity',

      // Telemetry
      cpu: 'CPU',
      ram: 'RAM',
      network: 'Network',
      telemetry_unavailable: 'Telemetry unavailable',
      telemetry_degraded: 'Degraded — Sentinel unreachable',
      unknown: 'unknown',

      // Alerts
      active_alerts: 'Active Alerts',
      no_active_alerts: 'No active alerts.',
      isolate: 'Isolate',
      escalate: 'Escalate',
      dismiss: 'Dismiss',
      authorize: 'Authorize',
      block: 'Block',

      // Classified action
      classified_action: 'Classified Action',
      classified_action_warning: 'You are about to execute {{action}}. This requires 4-eyes dual confirmation and step-up MFA.',
      justification_label: 'Justification / Ticket Link',
      justification_placeholder: 'INC-12345: Required to isolate node...',
      tap_fido2_step_up: 'Tap FIDO2 Key for Step-Up Auth',
      cancel: 'Cancel',
      execute_action: 'Execute Action',

      // Anti-tamper
      tampering_detected: 'Tampering Detected',
      self_destruct: 'System will self-destruct in',
      tap_fido2: 'Tap FIDO2 Key to Abort',
      fido2_waiting: 'Waiting for FIDO2 tap...',
      fido2_verifying: 'Verifying...',
      fido2_verified: 'Verified — aborting countdown',
      fido2_failed: 'Verification failed. Retry.',
      fido2_dev_mode: 'DEV MODE: simulating tap',
      mfa_token_prompt: 'Enter MFA token from FIDO2 device',

      // Consent
      consent_title: 'Department of Defense / National Security Warning',
      accept: 'I Accept',
      abort: 'Abort',

      // AI widget
      sentinel_agent: 'Sentinel Agent',
      ai_status_active: 'Active',
      ai_status_unknown: 'Status unknown',
      ai_model_unknown: 'Local model',
      ai_query_placeholder: 'Query the security agent...',
      ai_processing: 'Aegis is processing...',
      ai_error: 'Error: {{detail}}. Verify the Sentinel service is running.',
      ai_greeting: 'Hello, I am Aegis. Cyber-defence system active. How can I help?',
    },
  },
  'es-ES': {
    translation: {
      security_center: 'Centro de Seguridad Aegis',
      brand: 'HispanShield OS LLmSecurity',

      cpu: 'CPU',
      ram: 'RAM',
      network: 'Red',
      telemetry_unavailable: 'Telemetría no disponible',
      telemetry_degraded: 'Degradado — Sentinel inalcanzable',
      unknown: 'desconocido',

      active_alerts: 'Alertas Activas',
      no_active_alerts: 'Sin alertas activas.',
      isolate: 'Aislar',
      escalate: 'Escalar',
      dismiss: 'Descartar',
      authorize: 'Autorizar',
      block: 'Bloquear',

      classified_action: 'Acción Clasificada',
      classified_action_warning: 'Está a punto de ejecutar {{action}}. Requiere confirmación dual (4 ojos) y MFA step-up.',
      justification_label: 'Justificación / Enlace al ticket',
      justification_placeholder: 'INC-12345: Necesario para aislar nodo...',
      tap_fido2_step_up: 'Toque la llave FIDO2 para autenticación step-up',
      cancel: 'Cancelar',
      execute_action: 'Ejecutar Acción',

      tampering_detected: 'Manipulación Detectada',
      self_destruct: 'El sistema se autodestruirá en',
      tap_fido2: 'Toque Llave FIDO2 para Abortar',
      fido2_waiting: 'Esperando toque FIDO2...',
      fido2_verifying: 'Verificando...',
      fido2_verified: 'Verificado — abortando cuenta atrás',
      fido2_failed: 'Verificación fallida. Reintente.',
      fido2_dev_mode: 'MODO DEV: simulando toque',
      mfa_token_prompt: 'Introduzca el token MFA del dispositivo FIDO2',

      consent_title: 'Advertencia de Seguridad Nacional / DoD',
      accept: 'Acepto',
      abort: 'Abortar',

      sentinel_agent: 'Agente Sentinel',
      ai_status_active: 'Activo',
      ai_status_unknown: 'Estado desconocido',
      ai_model_unknown: 'Modelo local',
      ai_query_placeholder: 'Consulta al agente de seguridad...',
      ai_processing: 'Aegis está procesando...',
      ai_error: 'Error: {{detail}}. Verifique que el servicio Sentinel esté activo.',
      ai_greeting: 'Hola, soy Aegis. Sistema de defensa cibernética activo. ¿En qué puedo ayudarte?',
    },
  },
} as const;

i18n.use(initReactI18next).init({
  resources,
  lng: 'es-ES',
  fallbackLng: 'en-US',
  interpolation: {
    escapeValue: false,
  },
});

export default i18n;
