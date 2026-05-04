import React, { useState, useEffect } from 'react';
import { AlertOctagon, AlertTriangle, Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Alert {
  id: string;
  level: 'CRITICAL' | 'HIGH' | 'INFO';
  message: string;
  time: string;
}

export default function AlertTriagePanel() {
  const { t } = useTranslation();
  const [alerts, setAlerts] = useState<Alert[]>([
    { id: '1', level: 'CRITICAL', message: 'Unauthorized memory access blocked', time: '10:42:01' },
    { id: '2', level: 'HIGH', message: 'Suspicious outbound connection', time: '10:41:15' },
  ]);

  const handleAction = (id: string, action: string) => {
    setAlerts(alerts.filter(a => a.id !== id));
    console.log(`Action ${action} on alert ${id}`);
  };

  return (
    <div className="w-full flex flex-col gap-2">
      <h3 className="text-lg font-semibold text-white mb-2">{t('active_alerts')}</h3>
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
