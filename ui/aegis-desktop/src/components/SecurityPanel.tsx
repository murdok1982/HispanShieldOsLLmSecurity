import { invoke } from '@tauri-apps/api';
import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, AlertTriangle, CheckCircle } from 'lucide-react';

interface TelemetryData {
  cpu_usage_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  network_connections: number;
  timestamp: number;
}

export function SecurityPanel() {
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
        <h2 className="text-2xl font-bold text-white">Aegis Security Center</h2>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-gray-800/50 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5 text-green-400" />
            <span className="text-gray-300">CPU</span>
          </div>
          <div className="text-3xl font-bold text-white">
            {telemetry?.cpu_usage_percent.toFixed(1)}%
          </div>
        </div>

        <div className="bg-gray-800/50 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <Activity className="w-5 h-5 text-blue-400" />
            <span className="text-gray-300">RAM</span>
          </div>
          <div className="text-3xl font-bold text-white">
            {telemetry?.ram_used_mb}MB / {telemetry?.ram_total_mb}MB
          </div>
        </div>
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
        <button className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition-colors">
          <CheckCircle className="w-4 h-4 inline mr-2" />
          Autorizar
        </button>
        <button className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors">
          <AlertTriangle className="w-4 h-4 inline mr-2" />
          Bloquear
        </button>
      </div>
    </motion.div>
  );
}
