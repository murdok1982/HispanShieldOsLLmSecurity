import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Cpu, Lock, Activity, AlertTriangle } from 'lucide-react';

export default function SecurityPanel({ onClose }: { onClose: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95, y: 20 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95, y: 20 }}
      className="glass-panel"
      style={{
        position: 'absolute',
        top: '10%',
        left: '10%',
        width: '740px',
        height: '520px',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}
    >
      {/* Window Header */}
      <div style={{
        height: '38px',
        background: 'rgba(0,0,0,0.4)',
        display: 'flex',
        alignItems: 'center',
        padding: '0 16px',
        borderBottom: '1px solid var(--glass-border)',
        cursor: 'grab'
      }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <div onClick={onClose} style={{ width: 12, height: 12, borderRadius: '50%', background: '#FF5F56', cursor: 'pointer' }} />
          <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#FFBD2E' }} />
          <div style={{ width: 12, height: 12, borderRadius: '50%', background: '#27C93F' }} />
        </div>
        <div style={{ flex: 1, textAlign: 'center', fontSize: '13px', fontWeight: 600, color: 'rgba(255,255,255,0.8)' }}>
          Aegis Security Center
        </div>
      </div>

      {/* Body */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Sidebar */}
        <div style={{ width: '220px', borderRight: '1px solid var(--glass-border)', padding: '16px 8px' }}>
          <div style={{ marginBottom: '24px', paddingLeft: '8px' }}>
            <h3 style={{ fontSize: '11px', textTransform: 'uppercase', color: 'rgba(255,255,255,0.4)', letterSpacing: '1px' }}>Overview</h3>
          </div>
          {[ 
            { icon: <Shield size={16}/>, label: 'Policy Engine', active: true },
            { icon: <Cpu size={16}/>, label: 'Sentinel Core', active: false },
            { icon: <Activity size={16}/>, label: 'AegisEye Telemetry', active: false },
            { icon: <Lock size={16}/>, label: 'Allowed Tools', active: false }
          ].map((item, i) => (
            <div key={i} style={{
              display: 'flex', alignItems: 'center', gap: '12px', padding: '8px 12px', borderRadius: '6px',
              background: item.active ? 'var(--accent-color)' : 'transparent',
              color: item.active ? '#fff' : 'rgba(255,255,255,0.7)',
              cursor: 'pointer', marginBottom: '4px', fontSize: '14px', fontWeight: 500
            }}>
              {item.icon} {item.label}
            </div>
          ))}
        </div>

        {/* Main Content */}
        <div style={{ flex: 1, padding: '24px', overflowY: 'auto' }}>
          <h2 style={{ fontSize: '24px', fontWeight: 600, marginBottom: '20px' }}>Zero-Trust Audit Log</h2>
          
          <div style={{ background: 'rgba(0,0,0,0.5)', borderRadius: '8px', padding: '16px', marginBottom: '20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '12px' }}>
              <span style={{ fontSize: '14px', color: 'var(--success-color)' }}>● System Guard Active</span>
              <span className="mono-text" style={{ color: 'rgba(255,255,255,0.5)' }}>Mode: Strict</span>
            </div>
            <p style={{ fontSize: '13px', color: 'rgba(255,255,255,0.7)', lineHeight: 1.5 }}>
              All LLM invocations are intercepted by the Policy Engine. Free-shell execution is disabled.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <LogEntry time="13:42:01" type="ALLOW" source="AegisEye" msg="Context scraped successfully." />
            <LogEntry time="13:45:12" type="BLOCK" source="Policy Engine" msg="Blocked illegal tool 'shell_exec' from Agent." />
            <LogEntry time="13:47:33" type="HUMAN_REQ" source="Tool Router" msg="Agent requests network block. Waiting for user approval." />
            <div style={{ background: 'rgba(255,59,48,0.1)', border: '1px solid #FF3B30', padding: '12px', borderRadius: '8px', marginTop: '4px' }}>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center', marginBottom: '8px' }}>
                <AlertTriangle size={16} color="#FF3B30" />
                <strong style={{ fontSize: '14px' }}>Action Required</strong>
              </div>
              <p style={{ fontSize: '13px', marginBottom: '12px' }}>Sentinel Agent wants to isolate process PID 4921 due to anomalous behavior.</p>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button style={{ padding: '6px 12px', background: '#FF3B30', border: 'none', borderRadius: '4px', color: 'white', cursor: 'pointer' }}>Deny Action</button>
                <button style={{ padding: '6px 12px', background: 'transparent', border: '1px solid rgba(255,255,255,0.2)', borderRadius: '4px', color: 'white', cursor: 'pointer' }}>Allow Once</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function LogEntry({ time, type, source, msg }: { time: string, type: string, source: string, msg: string }) {
  const badgeColor = type === 'ALLOW' ? '#34C759' : type === 'BLOCK' ? '#FF3B30' : '#FF9F0A';
  return (
    <div style={{ display: 'flex', gap: '16px', fontSize: '13px', alignItems: 'flex-start', paddingBottom: '8px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
      <span className="mono-text" style={{ color: 'rgba(255,255,255,0.4)', minWidth: '70px' }}>{time}</span>
      <span style={{ color: badgeColor, fontWeight: 700, minWidth: '80px' }}>[{type}]</span>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <span style={{ color: 'rgba(255,255,255,0.6)', fontSize: '11px', textTransform: 'uppercase' }}>{source}</span>
        <span style={{ color: 'white' }}>{msg}</span>
      </div>
    </div>
  );
}
