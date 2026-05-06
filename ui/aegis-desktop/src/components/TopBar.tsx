import { useState, useEffect } from 'react';
import { Shield, Wifi, Battery, Search } from 'lucide-react';
import { invoke } from '@tauri-apps/api/tauri';
import { useTranslation } from 'react-i18next';

type SentinelStatus = 'unknown' | 'online' | 'degraded';

interface TelemetrySnapshot {
  cpu_usage_percent?: number;
  ram_used_mb?: number;
  ram_total_mb?: number;
}

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in window;
}

export default function TopBar() {
  const { t } = useTranslation();
  const [time, setTime] = useState(new Date());
  const [status, setStatus] = useState<SentinelStatus>('unknown');

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Probe de salud — si get_telemetry falla mostramos estado degradado en gris,
  // nunca un mock optimista verde.
  useEffect(() => {
    let cancelled = false;
    const probe = async () => {
      if (!isTauriRuntime()) {
        if (!cancelled) setStatus('unknown');
        return;
      }
      try {
        const raw = await invoke<string>('get_telemetry');
        const parsed = JSON.parse(raw) as TelemetrySnapshot;
        if (cancelled) return;
        setStatus(typeof parsed.cpu_usage_percent === 'number' ? 'online' : 'degraded');
      } catch {
        if (!cancelled) setStatus('degraded');
      }
    };
    probe();
    const id = setInterval(probe, 5000);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const dotColor =
    status === 'online' ? 'var(--color-phosphor)' :
    status === 'degraded' ? 'var(--color-amber)' :
    'var(--color-text-muted)';

  const dotLabel =
    status === 'online' ? t('ai_status_active') :
    status === 'degraded' ? t('telemetry_degraded') :
    t('ai_status_unknown');

  return (
    <div style={{
      height: '32px',
      width: '100%',
      background: 'rgba(20, 20, 25, 0.4)',
      backdropFilter: 'blur(30px)',
      borderBottom: '1px solid rgba(255,255,255,0.1)',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '0 16px',
      fontSize: '13px',
      fontWeight: 500,
      position: 'absolute',
      top: 24,
      zIndex: 9999,
      color: 'var(--color-text)',
      fontFamily: 'var(--font-sans)',
    }}>
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
        <Shield size={16} color="var(--color-phosphor)" />
        <span style={{ fontWeight: 600 }}>{t('brand')}</span>
        <span>File</span>
        <span>Edit</span>
        <span>View</span>
        <span>Security</span>
        <span>Help</span>
      </div>

      <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
        <span
          role="status"
          aria-label={dotLabel}
          title={dotLabel}
          style={{
            width: '10px',
            height: '10px',
            borderRadius: '50%',
            backgroundColor: dotColor,
            border: '1px solid rgba(0,0,0,0.4)',
            display: 'inline-block',
          }}
        />
        {status === 'unknown' && (
          <span style={{ color: 'var(--color-text-muted)', fontSize: '12px' }} aria-hidden="true">—</span>
        )}
        <Wifi size={14} />
        <Battery size={14} />
        <Search size={14} />
        <span>{time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      </div>
    </div>
  );
}
