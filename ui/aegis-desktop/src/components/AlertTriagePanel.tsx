import { useEffect, useState } from 'react';
import { AlertOctagon, AlertTriangle, Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { invoke } from '@tauri-apps/api/tauri';

type AlertLevel = 'CRITICAL' | 'HIGH' | 'INFO';

interface Alert {
  id: string;
  level: AlertLevel;
  message: string;
  time: string;
}

type RawAuditLine = string;

const POLL_INTERVAL_MS = 5000;
const MAX_ALERTS = 20;
const MESSAGE_MAX_CHARS = 120;
// Source of truth: leemos /var/log/hispanshield/audit.log via `get_audit_log`
// porque no existe un endpoint /alerts dedicado y duplicar el canal sería peor
// que reusar el log inmutable HMAC-firmado que ya escriben kernel, sentinel y UI.
const RELEVANT_LINE_RE = /SELF_DESTRUCT|TAMPER|ALERT|UI_AUDIT/;
// Timestamp ISO-8601 al inicio de la línea (formato común a todos los emisores).
const ISO_TS_RE = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)/;

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in window;
}

function classifyLevel(line: RawAuditLine): AlertLevel {
  if (/TAMPER|SELF_DESTRUCT/.test(line)) return 'CRITICAL';
  if (/WARN|denied/i.test(line)) return 'HIGH';
  return 'INFO';
}

function formatLocalTime(iso: string | null): string {
  if (!iso) return '--:--:--';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString();
}

// djb2: estable entre polls, evita duplicar entradas existentes en el state.
function hashLine(line: RawAuditLine): string {
  let h = 5381;
  for (let i = 0; i < line.length; i++) {
    h = ((h << 5) + h + line.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(16);
}

function parseAuditLines(lines: RawAuditLine[]): Alert[] {
  const out: Alert[] = [];
  for (const raw of lines) {
    if (!RELEVANT_LINE_RE.test(raw)) continue;
    const tsMatch = raw.match(ISO_TS_RE);
    const ts = tsMatch?.[1] ?? null;
    const rest = (tsMatch?.[0] ? raw.slice(tsMatch[0].length) : raw).trim();
    const message = rest.length > MESSAGE_MAX_CHARS
      ? `${rest.slice(0, MESSAGE_MAX_CHARS - 1)}…`
      : rest;
    out.push({
      id: hashLine(raw),
      level: classifyLevel(raw),
      message,
      time: formatLocalTime(ts),
    });
  }
  // Más recientes primero, capadas a MAX_ALERTS.
  return out.slice(-MAX_ALERTS).reverse();
}

export default function AlertTriagePanel() {
  const { t } = useTranslation();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [logError, setLogError] = useState<string | null>(null);
  const [browserDev] = useState<boolean>(() => !isTauriRuntime());

  useEffect(() => {
    if (browserDev) return;
    let cancelled = false;

    const fetchOnce = async () => {
      try {
        const lines = await invoke<RawAuditLine[]>('get_audit_log');
        if (cancelled) return;
        setAlerts(parseAuditLines(lines));
        setLogError(null);
      } catch (err) {
        if (cancelled) return;
        const detail = err instanceof Error ? err.message : String(err);
        setLogError(detail);
      }
    };

    void fetchOnce();
    const id = setInterval(() => { void fetchOnce(); }, POLL_INTERVAL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, [browserDev]);

  const handleAction = (id: string, action: string) => {
    setAlerts(prev => prev.filter(a => a.id !== id));
    if (browserDev) return;
    // Solo id+action: el contenido del alert ya vive en el log inmutable;
    // re-emitirlo aquí duplicaría payload y abriría una vía de eco.
    invoke('audit_event', {
      event: 'alert_triage_action',
      detail: { alert_id: id, action },
    }).catch(() => { /* logging best-effort, no rompemos UX local */ });
  };

  return (
    <div className="w-full flex flex-col gap-2">
      <h3 className="text-lg font-semibold text-white mb-2">{t('active_alerts')}</h3>

      {browserDev && (
        <p className="text-xs text-gray-500 italic">
          Browser dev mode — no live alerts
        </p>
      )}

      {logError && (
        <div
          role="status"
          className="text-xs text-yellow-300 bg-yellow-900/20 border border-yellow-700/40 rounded px-2 py-1"
        >
          audit log unavailable: {logError}
        </div>
      )}

      {alerts.length === 0 ? (
        <div className="text-gray-400 text-sm">No active alerts.</div>
      ) : (
        alerts.map(alert => (
          <div key={alert.id} className={`flex flex-col p-3 rounded-lg border ${
            alert.level === 'CRITICAL' ? 'border-red-500 bg-red-900/30 critical-pattern' :
            alert.level === 'HIGH' ? 'border-orange-500 bg-orange-900/30' :
            'border-blue-500 bg-blue-900/30'
          }`}>
            <div className="flex items-center gap-2 mb-2">
              {alert.level === 'CRITICAL' && <AlertOctagon size={16} className="text-red-400" />}
              {alert.level === 'HIGH' && <AlertTriangle size={16} className="text-orange-400" />}
              {alert.level === 'INFO' && <Info size={16} className="text-blue-400" />}
              <span className="font-bold text-white text-sm">{alert.level}</span>
              <span className="text-xs text-gray-400 ml-auto">{alert.time}</span>
            </div>
            <div className="text-white text-sm mb-3">{alert.message}</div>
            <div className="flex gap-2">
              <button onClick={() => handleAction(alert.id, 'isolate')} className="text-xs bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded text-white border border-gray-600">
                1: {t('isolate')}
              </button>
              <button onClick={() => handleAction(alert.id, 'escalate')} className="text-xs bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded text-white border border-gray-600">
                2: {t('escalate')}
              </button>
              <button onClick={() => handleAction(alert.id, 'dismiss')} className="text-xs bg-gray-800 hover:bg-gray-700 px-2 py-1 rounded text-white border border-gray-600">
                3: {t('dismiss')}
              </button>
            </div>
          </div>
        ))
      )}
    </div>
  );
}
