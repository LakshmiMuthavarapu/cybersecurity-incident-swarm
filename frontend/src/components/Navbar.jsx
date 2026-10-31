import React, { useState, useEffect } from 'react';
import { Clock, RefreshCw, Wifi } from 'lucide-react';

export default function Navbar({ onRefresh, isRefreshing, healthStatus }) {
  const [currentTime, setCurrentTime] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <div className="sim-indicator-pill">
          <span className="sim-pulse"></span>
          <span>SIMULATED SOC ENVIRONMENT</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.78rem', color: healthStatus?.database === 'connected' ? '#15803d' : '#b91c1c' }}>
          <Wifi size={14} />
          <span>{healthStatus?.database === 'connected' ? 'API Online' : 'Connecting API...'}</span>
        </div>
      </div>

      <div className="topbar-right">
        <div className="clock-display">
          <Clock size={13} />
          <span>{currentTime || 'Synchronizing UTC...'}</span>
        </div>

        <button
          className="btn btn-outline btn-sm"
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh Operations Telemetry"
        >
          <RefreshCw size={13} className={isRefreshing ? 'spin-animation' : ''} />
          <span>Refresh</span>
        </button>

        <div className="analyst-badge">
          <div className="analyst-avatar">AR</div>
          <div className="analyst-info">
            <span className="analyst-name">Alex Rivera</span>
            <span className="analyst-role">Lead Incident Analyst</span>
          </div>
        </div>
      </div>
    </header>
  );
}
