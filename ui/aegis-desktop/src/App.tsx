import { useState, useEffect } from 'react';
import './index.css';
import TopBar from './components/TopBar';
import Dock from './components/Dock';
import SecurityPanel from './components/SecurityPanel';
import AIWidget from './components/AIWidget';
import ClassificationBanner from './components/ClassificationBanner';
import ConsentScreen from './components/ConsentScreen';
import AntiTamperGate from './components/AntiTamperGate';

function App() {
  const [panelOpen, setPanelOpen] = useState(true);
  const [consented, setConsented] = useState(false);
  const [tampered, setTampered] = useState(false);

  // Tamper trigger is only available in development; production builds
  // never bind it on globalThis to keep destructive primitives off the JS surface.
  useEffect(() => {
    if (import.meta.env.DEV) {
      (globalThis as unknown as { triggerTamper?: () => void }).triggerTamper = () => setTampered(true);
    }
  }, []);

  if (!consented) {
    return <ConsentScreen onAccept={() => setConsented(true)} />;
  }

  return (
    <div style={{ width: '100vw', height: '100vh', position: 'relative' }}>
      <ClassificationBanner classification="PoC/Research (Unclassified)" />
      
      {tampered && <AntiTamperGate onAbort={() => setTampered(false)} />}
      
      <div className="desktop-bg" />
      <TopBar />
      <main style={{ position: 'absolute', top: '56px', left: 0, width: '100%', height: 'calc(100% - 80px)', pointerEvents: 'none', padding: '1.5rem' }}>
        <div style={{ width: '100%', height: '100%', position: 'relative', pointerEvents: 'auto' }}>
          {panelOpen && <SecurityPanel onClose={() => setPanelOpen(false)} />}
          <AIWidget />
        </div>
      </main>
      <Dock togglePanel={() => setPanelOpen(!panelOpen)} panelOpen={panelOpen} />
      
      <div style={{ position: 'absolute', bottom: 0, width: '100%' }}>
        <ClassificationBanner classification="PoC/Research (Unclassified)" />
      </div>
    </div>
  );
}

export default App;
