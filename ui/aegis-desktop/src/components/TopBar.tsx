import React, { useState, useEffect } from 'react';
import { Shield, Settings, Wifi, Battery, Search } from 'lucide-react';

export default function TopBar() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div style={{
      height: '32px',
      width: '100%',
      background: 'rgba(20, 20, 25, 0.4)',
      backdropFilter: 'blur(30px)',
      borderBottom: '1px solid rgba(255,255,255,0.1)',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      padding: '0 16px',
      fontSize: '13px',
      fontWeight: 500,
      position: 'absolute',
      top: 0,
      zIndex: 9999
    }}>
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
        <Shield size={16} color="var(--accent-color)" />
        <span style={{ fontWeight: 600 }}>HispanShield OS LLmSecurity</span>
        <span>File</span>
        <span>Edit</span>
        <span>View</span>
        <span>Security</span>
        <span>Help</span>
      </div>

      <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
        <div className="status-dot" title="AegisEye Active" />
        <Wifi size={14} />
        <Battery size={14} />
        <Search size={14} />
        <span>{time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
      </div>
    </div>
  );
}
