import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

const resources = {
  en: {
    translation: {
      "security_center": "Aegis Security Center",
      "cpu": "CPU",
      "ram": "RAM",
      "active_alerts": "Active Alerts",
      "isolate": "Isolate",
      "escalate": "Escalate",
      "dismiss": "Dismiss",
      "authorize": "Authorize",
      "block": "Block",
      "tampering_detected": "Tampering Detected",
      "self_destruct": "System will self-destruct in",
      "tap_fido2": "Tap FIDO2 Key to Abort",
      "consent_title": "Department of Defense / National Security Warning",
      "accept": "I Accept",
      "classified_action": "Classified Action"
    }
  },
  es: {
    translation: {
      "security_center": "Centro de Seguridad Aegis",
      "cpu": "CPU",
      "ram": "RAM",
      "active_alerts": "Alertas Activas",
      "isolate": "Aislar",
      "escalate": "Escalar",
      "dismiss": "Descartar",
      "authorize": "Autorizar",
      "block": "Bloquear",
      "tampering_detected": "Manipulación Detectada",
      "self_destruct": "El sistema se autodestruirá en",
      "tap_fido2": "Toque Llave FIDO2 para Abortar",
      "consent_title": "Advertencia de Seguridad Nacional / DoD",
      "accept": "Acepto",
      "classified_action": "Acción Clasificada"
    }
  }
};

i18n
  .use(initReactI18next)
  .init({
    resources,
    lng: "es", // default language
    fallbackLng: "en",
    interpolation: {
      escapeValue: false
    }
  });

export default i18n;
