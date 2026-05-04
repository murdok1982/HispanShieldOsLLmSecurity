import React, { useState, useEffect } from 'react';
import { ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  onAbort: () => void;
}

export default function AntiTamperGate({ onAbort }: Props) {
  const { t } = useTranslation();
  const [countdown, setCountdown] = useState(30);

  useEffect(() => {
    if (countdown <= 0) {
      onAbort();
      return;
    }
    const timer = setInterval(() => setCountdown(c => c - 1), 1000);
    return () => clearInterval(timer);
  }, [countdown, onAbort]);

  return (
    <div className="fixed inset-0 bg-red-950 z-[100000] flex flex-col items-center justify-center p-8 critical-pattern">
      <ShieldAlert size={120} className="text-white mb-8 animate-pulse" />
      <h1 className="text-6xl font-bold text-white mb-4 uppercase tracking-widest text-center">
        {t('tampering_detected')}
      </h1>
      <p className="text-2xl text-red-200 mb-12">{t('self_destruct')}</p>
      <div className="text-[120px] font-mono text-white font-bold leading-none mb-12">
        00:{countdown.toString().padStart(2, '0')}
      </div>
      <button 
        onClick={() => { /* Wait for FIDO2 tap in real app */ }}
        className="px-12 py-6 bg-transparent border-4 border-white text-white text-3xl font-bold rounded hover:bg-white hover:text-red-900 transition-colors uppercase tracking-widest"
      >
        {t('tap_fido2')}
      </button>
    </div>
  );
}
