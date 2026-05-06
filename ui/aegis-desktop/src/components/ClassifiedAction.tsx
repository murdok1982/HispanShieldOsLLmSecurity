import { useState } from 'react';
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
        className="px-4 py-2 rounded flex items-center gap-2 text-white text-sm font-semibold transition-colors"
        style={{
          backgroundColor: variant === 'danger'
            ? 'var(--color-classif-top-secret)'
            : 'var(--color-classif-secret)',
        }}
      >
        <Lock size={16} aria-hidden="true" />
        {actionName}
      </button>
    );
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="classified-action-title"
      className="fixed inset-0 flex items-center justify-center p-4"
      style={{
        // Sin backdrop-blur en panel crítico — fatiga visual en jornadas SOC de 12h
        backgroundColor: 'rgba(0,0,0,0.85)',
        zIndex: 'var(--z-modal)' as unknown as number,
      }}
    >
      <div
        className="p-6 rounded-lg max-w-md w-full"
        style={{
          backgroundColor: 'var(--color-panel)',
          border: '1px solid var(--color-border)',
          boxShadow: 'var(--shadow-modal)',
          color: 'var(--color-text)',
        }}
      >
        <div className="flex items-center gap-3 mb-4" style={{ color: 'var(--color-classif-secret)' }}>
          <ShieldAlert size={24} aria-hidden="true" />
          <h2 id="classified-action-title" className="text-xl font-bold uppercase tracking-wider" style={{ color: 'var(--color-text)' }}>
            {t('classified_action')}
          </h2>
        </div>
        <p className="text-sm mb-4" style={{ color: 'var(--color-text-dim)' }}>
          {t('classified_action_warning', { action: actionName })}
        </p>

        <div className="mb-4">
          <label htmlFor="classified-justification" className="block text-xs uppercase mb-1" style={{ color: 'var(--color-text-dim)' }}>
            {t('justification_label')}
          </label>
          <textarea
            id="classified-justification"
            className="w-full p-2 rounded text-sm focus:outline-none"
            style={{
              backgroundColor: 'var(--color-panel-2)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text)',
            }}
            rows={3}
            placeholder={t('justification_placeholder')}
            value={reason}
            onChange={e => setReason(e.target.value)}
          />
        </div>

        <div
          className="flex items-center gap-2 mb-6 p-3 rounded"
          style={{ backgroundColor: 'var(--color-panel-2)', border: '1px solid var(--color-border)' }}
        >
          <Lock size={16} style={{ color: 'var(--color-amber)' }} aria-hidden="true" />
          <span className="text-sm" style={{ color: 'var(--color-text)' }}>{t('tap_fido2_step_up')}</span>
        </div>

        <div className="flex gap-3 justify-end">
          <button
            onClick={() => setIsOpen(false)}
            className="px-4 py-2 transition-colors"
            style={{ color: 'var(--color-text-dim)' }}
          >
            {t('cancel')}
          </button>
          <button
            disabled={reason.length < 5}
            onClick={() => {
              onExecute(reason);
              setIsOpen(false);
            }}
            className="px-4 py-2 text-white rounded font-bold transition-colors disabled:opacity-40"
            style={{ backgroundColor: 'var(--color-classif-top-secret)' }}
          >
            {t('execute_action')}
          </button>
        </div>
      </div>
    </div>
  );
}
