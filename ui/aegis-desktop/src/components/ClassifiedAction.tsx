import React, { useState } from 'react';
import { Lock, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  actionName: string;
  onExecute: (reason: string) => void;
  variant?: 'danger' | 'warning';
}

export default function ClassifiedAction({ actionName, onExecute, variant = 'danger' }: Props) {
  const { t } = useTranslation();
  const [isOpen, setIsOpen] = useState(false);
  const [reason, setReason] = useState('');

  if (!isOpen) {
    return (
      <button 
        onClick={() => setIsOpen(true)}
        className={`px-4 py-2 rounded flex items-center gap-2 text-white text-sm font-semibold transition-colors ${
          variant === 'danger' ? 'bg-red-600 hover:bg-red-700' : 'bg-orange-600 hover:bg-orange-700'
        }`}
      >
        <Lock size={16} />
        {actionName}
      </button>
    );
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[9000] flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-700 p-6 rounded-lg max-w-md w-full shadow-2xl">
        <div className="flex items-center gap-3 text-orange-500 mb-4">
          <ShieldAlert size={24} />
          <h2 className="text-xl font-bold uppercase tracking-wider text-white">{t('classified_action')}</h2>
        </div>
        <p className="text-gray-300 text-sm mb-4">
          You are about to execute <strong>{actionName}</strong>. This requires 4-eyes dual confirmation and step-up MFA.
        </p>
        
        <div className="mb-4">
          <label className="block text-gray-400 text-xs uppercase mb-1">Justification / Ticket Link</label>
          <textarea 
            className="w-full bg-gray-800 border border-gray-700 text-white p-2 rounded text-sm focus:outline-none focus:border-orange-500"
            rows={3}
            placeholder="INC-12345: Required to isolate node..."
            value={reason}
            onChange={e => setReason(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-2 mb-6 p-3 bg-gray-800/50 rounded border border-gray-700">
          <Lock size={16} className="text-gray-400" />
          <span className="text-sm text-gray-300">Tap FIDO2 Key for Step-Up Auth</span>
        </div>

        <div className="flex gap-3 justify-end">
          <button 
            onClick={() => setIsOpen(false)}
            className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button 
            disabled={reason.length < 5}
            onClick={() => {
              onExecute(reason);
              setIsOpen(false);
            }}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-700 text-white rounded font-bold transition-colors"
          >
            Execute Action
          </button>
        </div>
      </div>
    </div>
  );
}
