import { motion } from 'framer-motion';
import { Terminal, ShieldAlert, Cpu, Activity, LayoutGrid } from 'lucide-react';

interface DockProps {
  togglePanel: () => void;
  panelOpen: boolean;
}

export default function Dock({ togglePanel, panelOpen }: DockProps) {
  const icons = [
    { id: 'finder', icon: <LayoutGrid size={24} color="#fff" /> },
    { id: 'terminal', icon: <Terminal size={24} color="#fff" /> },
    { id: 'security', icon: <ShieldAlert size={24} color={panelOpen ? "var(--accent-color)" : "#fff"} />, onClick: togglePanel },
    { id: 'monitor', icon: <Activity size={24} color="#fff" /> },
    { id: 'settings', icon: <Cpu size={24} color="#fff" /> },
  ];

  return (
    <div style={{
      position: 'absolute',
      bottom: '16px',
      left: '50%',
      transform: 'translateX(-50%)',
      zIndex: 9000
    }}>
      <div className="glass-panel" style={{
        display: 'flex',
        gap: '12px',
        padding: '8px 12px',
        borderRadius: '24px'
      }}>
        {icons.map(item => (
          <motion.div
            key={item.id}
            whileHover={{ scale: 1.2, y: -10 }}
            onClick={item.onClick}
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'rgba(255,255,255,0.1)',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              cursor: 'pointer',
              border: item.id === 'security' && panelOpen ? '1px solid var(--accent-color)' : '1px solid rgba(255,255,255,0.05)'
            }}
          >
            {item.icon}
          </motion.div>
        ))}
      </div>
    </div>
  );
}
