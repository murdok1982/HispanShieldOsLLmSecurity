import React, { useState } from 'react';
import { Bot, Send } from 'lucide-react';
import { motion } from 'framer-motion';

export default function AIWidget() {
  const [input, setInput] = useState('');

  return (
    <motion.div 
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      className="glass-panel"
      style={{
        position: 'absolute',
        top: '60px',
        right: '24px',
        width: '320px',
        padding: '16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px'
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--glass-border)', paddingBottom: '12px' }}>
        <div style={{ background: 'var(--accent-color)', padding: '6px', borderRadius: '8px' }}>
          <Bot size={20} color="white" />
        </div>
        <div>
          <h4 style={{ fontSize: '14px', fontWeight: 600 }}>Sentinel Agent</h4>
          <p style={{ fontSize: '11px', color: 'rgba(255,255,255,0.5)' }}>Qwen2.5-1.5B (Local)</p>
        </div>
        <div className="status-dot" style={{ marginLeft: 'auto' }} />
      </div>

      <div style={{
        height: '200px',
        overflowY: 'auto',
        fontSize: '13px',
        color: 'rgba(255,255,255,0.8)',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px',
        paddingRight: '4px'
      }}>
        <div style={{ background: 'rgba(255,255,255,0.1)', padding: '10px 14px', borderRadius: '12px 12px 12px 0', alignSelf: 'flex-start', maxWidth: '90%' }}>
          Sistema asegurado y telemetría capturada. ¿En qué te ayudo?
        </div>
      </div>

      <div style={{ position: 'relative', marginTop: 'auto' }}>
        <input 
          type="text" 
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask Sentinel..."
          style={{
            width: '100%',
            background: 'rgba(0,0,0,0.5)',
            border: '1px solid var(--glass-border)',
            borderRadius: '20px',
            padding: '10px 40px 10px 16px',
            color: 'white',
            outline: 'none',
            fontSize: '13px'
          }}
        />
        <button style={{
          position: 'absolute', right: '4px', top: '4px',
          background: 'var(--accent-color)', border: 'none',
          width: '28px', height: '28px', borderRadius: '50%',
          display: 'flex', justifyContent: 'center', alignItems: 'center',
          cursor: 'pointer'
        }}>
          <Send size={14} color="white" />
        </button>
      </div>
    </motion.div>
  );
}
