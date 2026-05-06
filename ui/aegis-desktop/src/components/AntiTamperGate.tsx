import { useState, useEffect, useCallback } from 'react';
import { ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { invoke } from '@tauri-apps/api/tauri';

interface Props {
  onAbort: () => void;
}

type TapState = 'idle' | 'waiting' | 'verifying' | 'verified' | 'failed';

// Doctrina: el contador NUNCA se pausa. O abortas a tiempo, o no abortas.
// El estado del tap solo cambia el feedback visual y habilita reintentos.
const TAMPER_COUNTDOWN_SECONDS = 30;
const DEV_TAP_DELAY_MS = 1000;

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in window;
}

async function performMfaVerification(token: string): Promise<boolean> {
  if (!isTauriRuntime()) {
    // Modo browser-dev: simulamos un tap exitoso tras 1s para poder iterar
    // sobre el flujo sin un FIDO2 físico. NUNCA debe ejecutarse en release.
    await new Promise(resolve => setTimeout(resolve, DEV_TAP_DELAY_MS));
    return true;
  }
  try {
    return await invoke<boolean>('verify_mfa', { token });
  } catch {
    return false;
  }
}

function logAuditEvent(event: string, detail: Record<string, unknown>): void {
  // Best-effort: si falla la fachada Tauri (modo dev) seguimos sin romper.
  // Usamos audit_event (canal directo HMAC al log inmutable) en lugar de /exec,
  // porque el camino del tamper no puede depender del allowlist del sentinel.
  if (!isTauriRuntime()) return;
  invoke('audit_event', { event, detail }).catch(() => {
    /* el countdown manda; no bloqueamos por logging */
  });
}

export default function AntiTamperGate({ onAbort }: Props) {
  const { t } = useTranslation();
  const [countdown, setCountdown] = useState(TAMPER_COUNTDOWN_SECONDS);
  const [tapState, setTapState] = useState<TapState>('idle');
  const [errorDetail, setErrorDetail] = useState<string | null>(null);

  useEffect(() => {
    if (countdown <= 0) {
      logAuditEvent('anti_tamper_timeout', { countdown_started: TAMPER_COUNTDOWN_SECONDS });
      onAbort();
      return;
    }
    const timer = setInterval(() => setCountdown(c => c - 1), 1000);
    return () => clearInterval(timer);
  }, [countdown, onAbort]);

  const handleTap = useCallback(async () => {
    if (tapState === 'verifying' || tapState === 'verified') return;

    setTapState('waiting');
    setErrorDetail(null);

    // Pedimos el token MFA. window.prompt es aceptable como fallback porque
    // el flujo real usa FIDO2 físico (PAM en host); aquí solo recogemos el OTP
    // que el dispositivo emite o que el operador introduce manualmente.
    const token = window.prompt(t('mfa_token_prompt')) ?? '';
    if (!token) {
      setTapState('idle');
      return;
    }

    setTapState('verifying');
    const ok = await performMfaVerification(token);

    if (ok) {
      setTapState('verified');
      logAuditEvent('anti_tamper_abort', { method: 'fido2_mfa', countdown_left: countdown });
      onAbort();
    } else {
      setTapState('failed');
      setErrorDetail(t('fido2_failed'));
      logAuditEvent('anti_tamper_mfa_failed', { countdown_left: countdown });
    }
  }, [tapState, t, onAbort, countdown]);

  const buttonLabel = (() => {
    switch (tapState) {
      case 'waiting': return t('fido2_waiting');
      case 'verifying': return t('fido2_verifying');
      case 'verified': return t('fido2_verified');
      case 'failed': return t('tap_fido2');
      default: return t('tap_fido2');
    }
  })();

  const isDevSimulating = !isTauriRuntime() && tapState === 'verifying';

  return (
    <div
      role="alertdialog"
      aria-modal="true"
      aria-labelledby="tamper-title"
      className="fixed inset-0 flex flex-col items-center justify-center p-8 critical-pattern"
      style={{
        backgroundColor: 'var(--color-classif-top-secret)',
        zIndex: 'var(--z-tamper)' as unknown as number,
      }}
    >
      <ShieldAlert size={120} className="text-white mb-8 animate-pulse" aria-hidden="true" />
      <h1 id="tamper-title" className="text-6xl font-bold text-white mb-4 uppercase tracking-widest text-center">
        {t('tampering_detected')}
      </h1>
      <p className="text-2xl text-red-100 mb-12">{t('self_destruct')}</p>
      <div
        className="text-[120px] font-bold leading-none mb-12 text-white"
        style={{ fontFamily: 'var(--font-mono)' }}
        aria-live="polite"
      >
        00:{countdown.toString().padStart(2, '0')}
      </div>

      <button
        onClick={handleTap}
        disabled={tapState === 'verifying' || tapState === 'verified'}
        className="px-12 py-6 bg-transparent border-4 border-white text-white text-3xl font-bold rounded hover:bg-white hover:text-red-900 transition-colors uppercase tracking-widest disabled:opacity-70 disabled:cursor-wait"
      >
        {buttonLabel}
      </button>

      {errorDetail && (
        <p role="alert" className="mt-6 text-xl font-bold text-white bg-black/40 px-4 py-2 rounded">
          {errorDetail}
        </p>
      )}
      {isDevSimulating && (
        <p className="mt-4 text-sm text-red-100 uppercase tracking-wider">
          {t('fido2_dev_mode')}
        </p>
      )}
    </div>
  );
}
