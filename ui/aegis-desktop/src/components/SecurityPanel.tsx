import { invoke } from '@tauri-apps/api';
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, AlertTriangle, CheckCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import AlertTriagePanel from './AlertTriagePanel';
import ClassifiedAction from './ClassifiedAction';

interface TelemetryData {
  cpu_usage_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  network_connections: number;
  timestamp: number;
}

export function SecurityPanel({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const [telemetry, setTelemetry] = useState<TelemetryData | null>(null);
  const [auditLog, setAuditLog] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const telData = await invoke<string>('get_telemetry');
        const tel = JSON.parse(telData);
        setTelemetry(tel);
        
        const logData = await invoke<string[]>('get_audit_log');
        setAuditLog(logData.slice(-10)); // Last 10 entries
      } catch (error) {
        console.error('Failed to fetch data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return <div className="p-4 text-white">Cargando Aegis Security Center...</div>;

  return (
    <motion.div 
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="bg-gray-900/80 backdrop-blur-xl rounded-2xl p-6 border border-cyan-500/20"
    >
      <div className="flex items-center gap-3 mb-6">
        <Shield className="w-8 h-8 text-cyan-400" />
        <h2 className="text-2xl font-bold text-white">{t('security_center')}</h2>
      </div>

      <div className="mb-6">
        <AlertTriagePanel />
      </div>

      <div className="mb-6">
        <h3 className="text-lg font-semibold text-white mb-3">Zero-Trust Audit Log</h3>
        <div className="bg-gray-800/50 rounded-xl p-4 max-h-64 overflow-y-auto">
          {auditLog.map((entry, idx) => (
            <div key={idx} className="text-sm text-gray-300 mb-1 font-mono">
              {entry}
            </div>
          ))}
        </div>
      </div>

      <div className="flex gap-3">
        <ClassifiedAction 
          actionName="ISOLATE NODE" 
          variant="danger" 
          onExecute={(reason) => console.log('Node isolated:', reason)} 
        />
        <ClassifiedAction 
          actionName="ESCALATE INCIDENT" 
          variant="warning" 
          onExecute={(reason) => console.log('Incident escalated:', reason)} 
        />
      </div>
    </motion.div>
  );
}
