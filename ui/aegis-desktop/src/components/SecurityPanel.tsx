import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, AlertTriangle, CheckCircle, AlertOctagon } from 'lucide-react';
import { invoke } from '@tauri-apps/api/tauri';
import { useTranslation } from 'react-i18next';

type Classification = 'CONFIDENCIAL' | 'SECRETO' | 'ALTO SECRETO';

interface TelemetryData {
  cpu_usage_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  network_connections: number;
  timestamp: number;
}

interface Alert {
  id: string;
  severity: 'CRITICAL' | 'WARNING' | 'INFO';
  message: string;
  timestamp: number;
  dismissed: boolean;
}

interface SecurityPanelProps {
  onClose?: () => void;
}

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in window;
}

export function SecurityPanel(_props: SecurityPanelProps = {}) {
  const { t } = useTranslation();
  const [telemetry, setTelemetry] = useState<TelemetryData | null>(null);
  const [telemetryError, setTelemetryError] = useState<string | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [classification] = useState<Classification>('CONFIDENCIAL');

  useEffect(() => {
    let cancelled = false;
    const fetchData = async () => {
      if (!isTauriRuntime()) {
        if (!cancelled) setTelemetryError(t('telemetry_unavailable'));
        return;
      }
      try {
        const telData = await invoke<string>('get_telemetry');
        const tel = JSON.parse(telData) as TelemetryData;
        if (cancelled) return;
        setTelemetry(tel);
        setTelemetryError(null);
      } catch (error) {
        if (cancelled) return;
        setTelemetry(null);
        setTelemetryError(error instanceof Error ? error.message : t('telemetry_degraded'));
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => { cancelled = true; clearInterval(interval); };
  }, [t]);

  const dismissAlert = (id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, dismissed: true } : a));
  };

  const activeAlerts = alerts.filter(a => !a.dismissed);

  const getAlertIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <AlertOctagon className="w-5 h-5" style={{ color: 'var(--color-critical)' }} aria-hidden="true" />;
      case 'WARNING': return <AlertTriangle className="w-5 h-5" style={{ color: 'var(--color-amber)' }} aria-hidden="true" />;
      default: return <CheckCircle className="w-5 h-5" style={{ color: 'var(--color-phosphor)' }} aria-hidden="true" />;
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      // backdrop-blur reducido (sm = 4px) por doctrina anti-fatiga SOC
      className="backdrop-blur-sm rounded-2xl p-6"
      style={{
        backgroundColor: 'var(--color-panel)',
        border: '1px solid var(--color-border)',
        color: 'var(--color-text)',
        boxShadow: 'var(--shadow-panel)',
      }}
    >
      <div className={`class-banner top-banner ${classification.toLowerCase().replace(' ', '-')}`}>
        {classification} // NOFORN
      </div>

      <div className="flex items-center gap-3 mb-6 mt-6">
        <Shield className="w-8 h-8" style={{ color: 'var(--color-phosphor)' }} aria-hidden="true" />
        <h2 className="text-2xl font-bold">{t('security_center')}</h2>
      </div>

      <div className="mb-6">
        <h3 className="text-lg font-semibold mb-3">
          {t('active_alerts')} ({activeAlerts.length})
        </h3>
        <div className="space-y-2 max-h-32 overflow-y-auto">
          {activeAlerts.length === 0 ? (
            <div className="text-sm" style={{ color: 'var(--color-text-dim)' }}>
              {t('no_active_alerts')}
            </div>
          ) : activeAlerts.map(alert => (
            <motion.div
              key={alert.id}
              initial={{ x: -20 }}
              animate={{ x: 0 }}
              className="alert-with-icon p-3 rounded-lg"
              style={{
                backgroundColor: alert.severity === 'CRITICAL' ? 'rgba(255,59,48,0.18)'
                  : alert.severity === 'WARNING' ? 'rgba(255,179,0,0.18)'
                  : 'var(--color-panel-2)',
                border: `1px solid ${alert.severity === 'CRITICAL' ? 'var(--color-critical)'
                  : alert.severity === 'WARNING' ? 'var(--color-amber)'
                  : 'var(--color-border)'}`,
              }}
            >
              {getAlertIcon(alert.severity)}
              <span className="flex-1">{alert.message}</span>
              <div className="flex gap-1">
                <button
                  className="px-2 py-1 text-xs rounded"
                  style={{ backgroundColor: 'var(--color-panel-2)', color: 'var(--color-text)', border: '1px solid var(--color-border)' }}
                >
                  1: {t('isolate')}
                </button>
                <button
                  className="px-2 py-1 text-xs rounded"
                  style={{ backgroundColor: 'var(--color-panel-2)', color: 'var(--color-text)', border: '1px solid var(--color-border)' }}
                >
                  2: {t('escalate')}
                </button>
                <button
                  className="px-2 py-1 text-xs rounded"
                  style={{ backgroundColor: 'var(--color-panel-2)', color: 'var(--color-text)', border: '1px solid var(--color-border)' }}
                  onClick={() => dismissAlert(alert.id)}
                >
                  3: {t('dismiss')}
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--color-panel-2)', border: '1px solid var(--color-border)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5" style={{ color: 'var(--color-phosphor)' }} aria-hidden="true" />
            <span style={{ color: 'var(--color-text-dim)' }}>{t('cpu')}</span>
          </div>
          <div className="text-3xl font-bold" style={{ fontFamily: 'var(--font-mono)' }}>
            {telemetry ? `${telemetry.cpu_usage_percent.toFixed(1)}%` : '—'}
          </div>
        </div>

        <div className="rounded-xl p-4" style={{ backgroundColor: 'var(--color-panel-2)', border: '1px solid var(--color-border)' }}>
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5" style={{ color: 'var(--color-phosphor)' }} aria-hidden="true" />
            <span style={{ color: 'var(--color-text-dim)' }}>{t('ram')}</span>
          </div>
          <div className="text-3xl font-bold" style={{ fontFamily: 'var(--font-mono)' }}>
            {telemetry ? `${telemetry.ram_used_mb}MB / ${telemetry.ram_total_mb}MB` : '—'}
          </div>
        </div>
      </div>

      {telemetryError && (
        <p role="status" className="text-xs mb-4" style={{ color: 'var(--color-amber)' }}>
          {telemetryError}
        </p>
      )}

      <div className="flex gap-3">
        <button
          className="px-4 py-2 text-white rounded-lg transition-colors"
          style={{ backgroundColor: 'var(--color-classif-unclassified)' }}
        >
          <CheckCircle className="w-4 h-4 inline mr-2" aria-hidden="true" />
          {t('authorize')}
        </button>
        <button
          className="px-4 py-2 text-white rounded-lg transition-colors"
          style={{ backgroundColor: 'var(--color-critical)' }}
        >
          <AlertTriangle className="w-4 h-4 inline mr-2" aria-hidden="true" />
          {t('block')}
        </button>
      </div>

      <div className={`class-banner bottom-banner ${classification.toLowerCase().replace(' ', '-')}`}>
        {classification} // NOFORN
      </div>
    </motion.div>
  );
}

export default SecurityPanel;
