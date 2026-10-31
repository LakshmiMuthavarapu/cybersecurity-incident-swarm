import React from 'react';
import {
  LayoutDashboard,
  BellRing,
  ShieldAlert,
  SearchCode,
  Binary,
  CheckSquare,
  History,
  Cpu,
  Layers,
} from 'lucide-react';

export default function Sidebar({ activePage, setActivePage, pendingApprovalsCount = 0 }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'alerts', label: 'Security Alerts', icon: BellRing },
    { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
    { id: 'investigation', label: 'Investigation Console', icon: SearchCode },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Binary },
    {
      id: 'approvals',
      label: 'Approvals Queue',
      icon: CheckSquare,
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : null,
    },
    { id: 'audit-logs', label: 'SOC Audit Logs', icon: History },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="brand-icon-wrapper">
          <Layers size={22} />
        </div>
        <div className="brand-text">
          <h1>CYBERSWARM</h1>
          <span>Simulated SOC Operations</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activePage === item.id;
          return (
            <button
              key={item.id}
              className={`nav-link ${isActive ? 'active' : ''}`}
              onClick={() => setActivePage(item.id)}
            >
              <Icon size={18} />
              <span>{item.label}</span>
              {item.badge && <span className="nav-badge">{item.badge}</span>}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="swarm-status-box">
          <div className="swarm-status-header">
            <span className="status-dot-pulse"></span>
            <span>Swarm Core (Active)</span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.72rem', marginTop: '2px' }}>
            Deterministic Correlation Engine
          </p>
          <div style={{ marginTop: '6px', paddingTop: '6px', borderTop: '1px solid #f1f5f9', display: 'flex', alignItems: 'center', gap: '4px', color: '#0369a1', fontSize: '0.7rem', fontWeight: 600 }}>
            <Cpu size={12} />
            <span>Four-Agent Workflow Ready</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
