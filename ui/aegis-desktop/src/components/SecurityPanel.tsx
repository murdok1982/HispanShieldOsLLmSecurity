import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Activity, AlertTriangle, CheckCircle, AlertOctagon } from 'lucide-react';

// Classification levels (U1 FIX: Persistent banner)
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

export function SecurityPanel() {
  const [telemetry, setTelemetry] = useState<TelemetryData | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([
    { id: '1', severity: 'CRITICAL', message: 'CPU 95% - Possible compromis', timestamp: Date.now(), dismissed: false },
    { id: '2', severity: 'WARNING', message: 'Unusual network traffic detected', timestamp: Date.now(), dismissed: false },
  { id: '3', severity: 'INFO', message: 'System audit passed', timestamp: Date.now(), dismissed: false },
  ]);
  const [classification] = useState<Classification>('CONFIDENCIAL');
  const [consentShown, setConsentShown] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const telData = await invoke<string>('get_telemetry');
        const tel = JSON.parse(telData);
        setTelemetry(tel);
      } catch (error) {
        console.error('Failed to fetch telemetry:', error);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const dismissAlert = (id: string) => {
    setAlerts(prev => prev.map(a => a.id === id ? { ...a, dismissed: true } : a));
  };

  const activeAlerts = alerts.filter(a => !a.dismissed);

  // WCAG AAA contrast: dark background + white text
  const panelClass = classification === 'ALTO SECRETO' 
    ? 'bg-gray-900/95 text-white' 
    : 'bg-gray-900/90 text-white';

  // U4 FIX: No color-only alerts - use icons + patterns
  const getAlertIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return <AlertOctagon className="w-5 h-5 text-red-500" />;
      case 'WARNING': return <AlertTriangle className="w-5 h-5 text-yellow-500" />;
      default: return <CheckCircle className="w-5 h-5 text-green-500" />;
    }
  };

  if (consentShown) {
    return (
      <motion.div 
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="consent-screen"
      >
        <Shield className="w-20 h-20 text-amber-400 mb-6" />
        <h1 className="text-3xl font-bold mb-4">Aegis Security Center</h1>
        <p className="text-lg mb-2">Classification: <span className={classification.toLowerCase().replace(' ', '-')}>{classification}</span></p>
        <p className="text-sm text-gray-400 mb-8 max-w-md text-center">
          This system is RESTRICTED. Unauthorized access is prohibited. 
          All activities are monitored and recorded.
          By clicking ACCEPT, you agree to the Terms of Use and Privacy Policy.
        </p>
        <div className="flex gap-4">
          <button 
            className="consent-button consent-abort"
            onClick={() => window.close()}
          >
            ABORT (ESC)
          </button>
          <button 
            className="consent-button consent-accept"
            onClick={() => setConsentShown(false)}
          >
            ACCEPT (Enter)
          </button>
        </div>
        <p className="text-xs text-gray-500 mt-4">Timestamp: {new Date().toISOString()}</p>
      </motion.div>
    );
  }

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className={`${panelClass} backdrop-blur-sm rounded-2xl p-6 border border-cyan-500/20`}
    >
      {/* U1 FIX: Persistent classification banner */}
      <div className={`class-banner top-banner ${classification.toLowerCase().replace(' ', '-')}`}>
        {classification} // NOFORN
      </div>

      <div className="flex items-center gap-3 mb-6 mt-6">
        <Shield className="w-8 h-8 text-cyan-400" />
        <h2 className="text-2xl font-bold text-white">Aegis Security Center</h2>
      </div>

      {/* Alert Triage Panel (U4 FIX: Time-to-action ≤2s) */}
      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-3">Active Alerts ({activeAlerts.length})</h3>
        <div className="space-y-2 max-h-32 overflow-y-auto">
          {activeAlerts.map(alert => (
            <motion.div
              key={alert.id}
              initial={{ x: -20 }}
              animate={{ x: 0 }}
              className={`alert-with-icon p-3 rounded-lg ${
                alert.severity === 'CRITICAL' ? 'alert-critical' : 
                alert.severity === 'WARNING' ? 'alert-warning' : 'bg-gray-800/50'
              }`}
            >
              {getAlertIcon(alert.severity)}
              <span className="flex-1">{alert.message}</span>
              <div className="flex gap-1">
                <button className="px-2 py-1 bg-blue-600 hover:bg-blue-700 text-xs rounded">1: Isolate</button>
                <button className="px-2 py-1 bg-yellow-600 hover:bg-yellow-700 text-xs rounded">2: Escalate</button>
                <button 
                  className="px-2 py-1 bg-gray-600 hover:bg-gray-700 text-xs rounded"
                  onClick={() => dismissAlert(alert.id)}
                >
                  3: Dismiss
                </button>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {telemetry && (
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="bg-gray-800/50 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-5 h-5 text-green-400" />
              <span className="text-gray-300">CPU</span>
            </div>
            <div className="text-3xl font-bold text-white">
              {telemetry.cpu_usage_percent.toFixed(1)}%
            </div>
          </div>

          <div className="bg-gray-800/50 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <Activity className="w-5 h-5 text-blue-400" />
              <span className="text-gray-300">RAM</span>
            </div>
            <div className="text-3xl font-bold text-white">
              {telemetry.ram_used_mb}MB / {telemetry.ram_total_mb}MB
            </div>
          </div>
        </div>
      )}

      <div className="flex gap-3">
        <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors">
          <CheckCircle className="w-4 h-4 inline mr-2" />
          Autorizar
        </button>
        <button className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors">
          <AlertTriangle className="w-4 h-4 inline mr-2" />
          Bloquear
        </button>
      </div>

      {/* U1 FIX: Bottom classification banner */}
      <div className={`class-banner bottom-banner ${classification.toLowerCase().replace(' ', '-')}`}>
        {classification} // NOFORN
      </div>
    </motion.div>
  );
}
