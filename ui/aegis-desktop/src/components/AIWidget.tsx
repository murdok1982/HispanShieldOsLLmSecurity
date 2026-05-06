import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Bot, User, Shield } from 'lucide-react';
import { invoke } from '@tauri-apps/api/tauri';
import { useTranslation } from 'react-i18next';

interface Message {
  role: 'user' | 'agent';
  content: string;
  timestamp?: number;
}

interface AgentInfo {
  model: string;
  status: 'online' | 'unknown';
}

function isTauriRuntime(): boolean {
  return typeof window !== 'undefined' && '__TAURI_IPC__' in window;
}

interface RuntimeInfoResponse {
  model?: string;
}

export default function AIWidget() {
  const { t } = useTranslation();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [agent, setAgent] = useState<AgentInfo>({ model: t('ai_model_unknown'), status: 'unknown' });

  // Saludo inicial localizado — antes estaba hardcoded en español
  useEffect(() => {
    setMessages([{ role: 'agent', content: t('ai_greeting'), timestamp: Date.now() }]);
  }, [t]);

  // Descubrimiento del modelo del Sentinel — sin hardcodear "Qwen2.5".
  // Si Sentinel no responde, queda como "unknown" + dot gris (no verde mock).
  useEffect(() => {
    let cancelled = false;
    const discover = async () => {
      if (!isTauriRuntime()) {
        if (!cancelled) setAgent({ model: t('ai_model_unknown'), status: 'unknown' });
        return;
      }
      try {
        // runtime_info es un Tauri command dedicado (no pasa por el allowlist
        // del sentinel) que lee /etc/hispanshield/runtime.json provisionado por
        // el installer. Si no está provisto, status="unprovisioned" y el dot
        // queda gris — nunca verde mock.
        const info = await invoke<RuntimeInfoResponse & { status?: string }>('runtime_info');
        if (cancelled) return;
        const provisioned = info.status !== 'unprovisioned' && typeof info.model === 'string' && info.model.length > 0;
        setAgent({
          model: provisioned ? (info.model as string) : t('ai_model_unknown'),
          status: provisioned ? 'online' : 'unknown',
        });
      } catch {
        if (!cancelled) setAgent({ model: t('ai_model_unknown'), status: 'unknown' });
      }
    };
    discover();
  }, [t]);

  const sendMessage = async () => {
    if (!input.trim()) return;

    const userMessage = input;
    setMessages(prev => [...prev, { role: 'user', content: userMessage, timestamp: Date.now() }]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await invoke<string>('send_command', {
        tool: 'ai_query',
        args: JSON.stringify({ query: userMessage }),
      });

      setMessages(prev => [...prev, {
        role: 'agent',
        content: response,
        timestamp: Date.now(),
      }]);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      setMessages(prev => [...prev, {
        role: 'agent',
        content: t('ai_error', { detail }),
        timestamp: Date.now(),
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const statusColor = agent.status === 'online' ? 'var(--color-phosphor)' : 'var(--color-text-muted)';
  const statusLabel = agent.status === 'online' ? t('ai_status_active') : t('ai_status_unknown');

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-900/90 backdrop-blur-sm rounded-2xl overflow-hidden"
      style={{ border: '1px solid var(--color-border)' }}
    >
      <div className="bg-gray-800/50 p-4" style={{ borderBottom: '1px solid var(--color-border)' }}>
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-full flex items-center justify-center"
            style={{ backgroundColor: 'var(--color-panel-2)', border: '1px solid var(--color-border)' }}
          >
            <Bot className="w-6 h-6" style={{ color: 'var(--color-phosphor)' }} />
          </div>
          <div>
            <h3 className="font-semibold" style={{ color: 'var(--color-text)' }}>{t('sentinel_agent')}</h3>
            <p className="text-xs flex items-center gap-2" style={{ color: 'var(--color-text-dim)' }}>
              <span
                aria-label={statusLabel}
                title={statusLabel}
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: statusColor,
                  display: 'inline-block',
                }}
              />
              {agent.model} · {statusLabel}
            </p>
          </div>
          <Shield className="w-5 h-5 ml-auto" style={{ color: statusColor }} aria-hidden="true" />
        </div>
      </div>

      <div className="h-64 overflow-y-auto p-4 space-y-3">
        <AnimatePresence>
          {messages.map((msg, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, x: msg.role === 'user' ? 20 : -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`flex gap-2 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'agent' && (
                <div
                  className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: 'var(--color-panel-2)' }}
                >
                  <Bot className="w-5 h-5" style={{ color: 'var(--color-phosphor)' }} />
                </div>
              )}
              <div
                className="max-w-[80%] p-3 rounded-2xl"
                style={{
                  backgroundColor: msg.role === 'user' ? 'var(--color-panel-2)' : 'var(--color-panel)',
                  color: 'var(--color-text)',
                  border: '1px solid var(--color-border)',
                }}
              >
                {msg.content}
                {msg.timestamp && (
                  <div className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                )}
              </div>
              {msg.role === 'user' && (
                <div
                  className="w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0"
                  style={{ backgroundColor: 'var(--color-panel-2)' }}
                >
                  <User className="w-5 h-5" style={{ color: 'var(--color-text-dim)' }} />
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
        {isLoading && (
          <div className="text-sm" style={{ color: 'var(--color-text-dim)' }}>{t('ai_processing')}</div>
        )}
      </div>

      <div className="p-4" style={{ borderTop: '1px solid var(--color-border)' }}>
        <div className="flex gap-2">
          <label htmlFor="ai-query-input" className="sr-only">
            {t('ai_query_placeholder')}
          </label>
          <input
            id="ai-query-input"
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') void sendMessage(); }}
            placeholder={t('ai_query_placeholder')}
            className="flex-1 rounded-lg px-4 py-2 focus:outline-none"
            style={{
              backgroundColor: 'var(--color-panel-2)',
              color: 'var(--color-text)',
              border: '1px solid var(--color-border)',
            }}
          />
          <button
            onClick={() => void sendMessage()}
            disabled={isLoading}
            aria-label={t('ai_query_placeholder')}
            className="px-4 py-2 rounded-lg transition-colors disabled:opacity-50"
            style={{
              backgroundColor: 'var(--color-panel-2)',
              color: 'var(--color-phosphor)',
              border: '1px solid var(--color-border)',
            }}
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}
