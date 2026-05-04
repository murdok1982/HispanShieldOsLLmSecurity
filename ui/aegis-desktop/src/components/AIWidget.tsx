import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Send, Bot, User, Shield, AlertTriangle } from 'lucide-react';
import { invoke } from '@tauri-apps/api';

interface Message {
  role: 'user' | 'agent';
  content: string;
  timestamp?: number;
}

export function AIWidget() {
  const [messages, setMessages] = useState<Message[]>([
    { 
      role: 'agent', 
      content: 'Hola, soy Aegis. Sistema de defensa cibernética activo. ¿En qué puedo ayudarte?',
      timestamp: Date.now()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const sendMessage = async () => {
    if (!input.trim()) return;
    
    const userMessage = input;
    setMessages(prev => [...prev, { role: 'user', content: userMessage, timestamp: Date.now() }]);
    setInput('');
    setIsLoading(true);

    try {
      // CWE-942 FIX: Send to local Sentinel only (no external calls)
      const response = await invoke<string>('send_command', {
        tool: 'ai_query',
        args: JSON.stringify({ query: userMessage })
      });
      
      setMessages(prev => [...prev, { 
        role: 'agent', 
        content: response,
        timestamp: Date.now()
      }]);
    } catch (error) {
      setMessages(prev => [...prev, { 
        role: 'agent', 
        content: `Error: ${error}. Verifique que el servicio Sentinel esté activo.`,
        timestamp: Date.now()
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-gray-900/90 backdrop-blur-sm rounded-2xl border border-cyan-500/20 overflow-hidden"
    >
      <div className="bg-gray-800/50 p-4 border-b border-cyan-500/20">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-400 to-blue-600 flex items-center justify-center">
            <Bot className="w-6 h-6 text-white" />
          </div>
          <div>
            <h3 className="text-white font-semibold">Sentinel Agent</h3>
            <p className="text-xs text-gray-400">Qwen2.5 Local | Estado: Activo</p>
          </div>
          <Shield className="w-5 h-5 text-green-400 ml-auto" />
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
                <div className="w-8 h-8 rounded-full bg-cyan-600 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-5 h-5 text-white" />
                </div>
              )}
              <div className={`max-w-[80%] p-3 rounded-2xl ${
                msg.role === 'user' 
                  ? 'bg-blue-600 text-white' 
                  : 'bg-gray-800 text-gray-100'
              }`}>
                {msg.content}
                {msg.timestamp && (
                  <div className="text-xs text-gray-400 mt-1">
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                )}
              </div>
              {msg.role === 'user' && (
                <div className="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center flex-shrink-0">
                  <User className="w-5 h-5 text-white" />
                </div>
              )}
            </motion.div>
          ))}
        </AnimatePresence>
        {isLoading && (
          <div className="text-gray-400 text-sm">Aegis está procesando...</div>
        )}
      </div>

      <div className="p-4 border-t border-gray-700">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            placeholder="Consulta al agente de seguridad..."
            className="flex-1 bg-gray-800 text-white rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <button
            onClick={sendMessage}
            disabled={isLoading}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 disabled:bg-gray-700 text-white rounded-lg transition-colors"
          >
            <Send className="w-5 h-5" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}
