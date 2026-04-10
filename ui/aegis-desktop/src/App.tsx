import React, { useState } from 'react';
import './index.css';
import TopBar from './components/TopBar';
import Dock from './components/Dock';
import SecurityPanel from './components/SecurityPanel';
import AIWidget from './components/AIWidget';

function App() {
  const [panelOpen, setPanelOpen] = useState(true);

  return (
    <div style={{ width: '100vw', height: '100vh', position: 'relative' }}>
      <div className="desktop-bg" />
      <TopBar />
      <main style={{ position: 'absolute', top: '32px', left: 0, width: '100%', height: 'calc(100% - 32px)', pointerEvents: 'none', padding: '1.5rem' }}>
        <div style={{ width: '100%', height: '100%', position: 'relative', pointerEvents: 'auto' }}>
          {panelOpen && <SecurityPanel onClose={() => setPanelOpen(false)} />}
          <AIWidget />
        </div>
      </main>
      <Dock togglePanel={() => setPanelOpen(!panelOpen)} panelOpen={panelOpen} />
    </div>
  );
}

export default App;
