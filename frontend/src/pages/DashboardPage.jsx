import React from 'react';
import {
  BellRing,
  ShieldAlert,
  Flame,
  Clock,
  CheckSquare,
  ArrowRight,
  Activity,
  Terminal,
} from 'lucide-react';
import StatCard from '../components/StatCard';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import SimBanner from '../components/SimBanner';

export default function DashboardPage({ stats, onNavigate, onSelectIncident }) {
  if (!stats) {
    return (
      <div className="page-body">
        <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
          Loading SOC Dashboard Telemetry...
        </div>
      </div>
    );
  }

  const {
    total_alerts = 0,
    open_incidents = 0,
    critical_incidents = 0,
    incidents_awaiting_review = 0,
    pending_approvals = 0,
    alerts_by_severity = [],
    alerts_by_category = [],
    recent_incidents = [],
    recent_alerts = [],
    pending_approval_items = [],
  } = stats;

  return (
    <div className="page-body">
      <SimBanner />

      <div className="page-header">
        <div className="page-title-group">
          <h2>Security Operations Center Dashboard</h2>
          <p>
            Autonomous correlation and triage swarm monitoring simulated endpoint, network, and cloud telemetry.
          </p>
        </div>
      </div>

      {/* 4 Core KPIs + Pending Approvals */}
      <div className="stats-grid">
        <StatCard
          title="Total Security Alerts"
          value={total_alerts}
          icon={BellRing}
          color="blue"
          subtitle="Telemetry ingestion across all sensors"
          onClick={() => onNavigate('alerts')}
        />
        <StatCard
          title="Open Incidents"
          value={open_incidents}
          icon={ShieldAlert}
          color="amber"
          subtitle="Active investigations under analysis"
          onClick={() => onNavigate('incidents')}
        />
        <StatCard
          title="Critical Incidents"
          value={critical_incidents}
          icon={Flame}
          color="red"
          subtitle="Immediate containment priority"
          onClick={() => onNavigate('incidents')}
        />
        <StatCard
          title="Awaiting Review"
          value={incidents_awaiting_review}
          icon={Clock}
          color="purple"
          subtitle="Swarm correlations requiring sign-off"
          onClick={() => onNavigate('incidents')}
        />
        <StatCard
          title="Pending Approvals"
          value={pending_approvals}
          icon={CheckSquare}
          color="orange"
          subtitle="Containment action proposals"
          onClick={() => onNavigate('approvals')}
        />
      </div>

      {/* Main Grid: Distribution & Quick Actions */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* Severity & Category Breakdown */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <span className="card-title">
              <Activity size={18} color="var(--primary)" />
              Telemetry Distribution by Severity
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Deterministic Classification</span>
          </div>
          <div className="card-body">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {alerts_by_severity.map((item) => {
                const total = Math.max(total_alerts, 1);
                const percent = Math.round((item.count / total) * 100);
                let barColor = '#0284c7';
                if (item.severity === 'CRITICAL') barColor = '#dc2626';
                if (item.severity === 'HIGH') barColor = '#ea580c';
                if (item.severity === 'MEDIUM') barColor = '#d97706';
                if (item.severity === 'LOW') barColor = '#16a34a';

                return (
                  <div key={item.severity}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '4px', fontWeight: 600 }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: barColor }}></span>
                        {item.severity}
                      </span>
                      <span>
                        {item.count} alerts ({percent}%)
                      </span>
                    </div>
                    <div style={{ height: '8px', background: '#f1f5f9', borderRadius: '999px', overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${percent}%`, backgroundColor: barColor, borderRadius: '999px' }}></div>
                    </div>
                  </div>
                );
              })}
            </div>

            <div style={{ marginTop: '1.25rem', paddingTop: '1rem', borderTop: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                Top MITRE Attack Categories
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {alerts_by_category.map((cat) => (
                  <span
                    key={cat.category}
                    style={{
                      background: 'var(--bg-surface-subtle)',
                      padding: '0.3rem 0.6rem',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.78rem',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    {cat.category}: <strong>{cat.count}</strong>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Pending Containment Approvals Queue */}
        <div className="card" style={{ marginBottom: 0 }}>
          <div className="card-header">
            <span className="card-title">
              <CheckSquare size={18} color="#ea580c" />
              Containment Approvals Awaiting Decision
            </span>
            <button className="btn btn-outline btn-sm" onClick={() => onNavigate('approvals')}>
              View Queue ({pending_approvals})
            </button>
          </div>
          <div className="card-body">
            {pending_approval_items.length === 0 ? (
              <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No containment actions currently awaiting analyst authorization.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {pending_approval_items.map((app) => (
                  <div
                    key={app.id}
                    style={{
                      padding: '0.85rem',
                      borderRadius: 'var(--radius-md)',
                      border: '1px solid var(--border-subtle)',
                      background: 'white',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                        {app.action_type}
                      </span>
                      <SeverityBadge severity={app.risk_level} />
                    </div>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      Target: <strong className="mono">{app.target}</strong>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '0.25rem' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        Proposed by: {app.proposed_by}
                      </span>
                      <button
                        className="btn btn-primary btn-sm"
                        onClick={() => onNavigate('approvals')}
                      >
                        Review Action
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Critical & Active Incidents Table */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <ShieldAlert size={18} color="#dc2626" />
            Priority Incident Investigations
          </span>
          <button className="btn btn-outline btn-sm" onClick={() => onNavigate('incidents')}>
            All Incidents <ArrowRight size={13} />
          </button>
        </div>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Severity</th>
                <th>Title & Vector</th>
                <th>Status</th>
                <th>Risk Score</th>
                <th>Lead Analyst</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {recent_incidents.map((inc) => (
                <tr key={inc.id}>
                  <td className="mono" style={{ fontWeight: 700, color: 'var(--primary)' }}>
                    {inc.id}
                  </td>
                  <td>
                    <SeverityBadge severity={inc.severity} />
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{inc.title}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{inc.attack_vector}</div>
                  </td>
                  <td>
                    <StatusBadge status={inc.status} />
                  </td>
                  <td>
                    <div className="risk-meter">
                      <div className="risk-bar-track">
                        <div
                          className="risk-bar-fill"
                          style={{
                            width: `${inc.risk_score}%`,
                            backgroundColor: inc.risk_score >= 80 ? '#dc2626' : inc.risk_score >= 50 ? '#d97706' : '#16a34a',
                          }}
                        ></div>
                      </div>
                      <span style={{ fontWeight: 700, fontSize: '0.8rem' }}>{inc.risk_score}</span>
                    </div>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{inc.lead_analyst}</td>
                  <td>
                    <button
                      className="btn btn-outline btn-sm"
                      onClick={() => onSelectIncident(inc.id)}
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent Alerts Feed */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <Terminal size={18} color="var(--primary)" />
            Real-Time Telemetry Feed (Simulated Sensors)
          </span>
          <button className="btn btn-outline btn-sm" onClick={() => onNavigate('alerts')}>
            View All Alerts <ArrowRight size={13} />
          </button>
        </div>
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Timestamp (UTC)</th>
                <th>Alert Title</th>
                <th>Source Sensor</th>
                <th>Target Host / User</th>
                <th>Category</th>
              </tr>
            </thead>
            <tbody>
              {recent_alerts.map((alt) => (
                <tr key={alt.id}>
                  <td className="mono" style={{ fontWeight: 600 }}>{alt.id}</td>
                  <td><SeverityBadge severity={alt.severity} /></td>
                  <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {new Date(alt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </td>
                  <td style={{ fontWeight: 600 }}>{alt.title}</td>
                  <td style={{ fontSize: '0.8rem' }}>{alt.source}</td>
                  <td className="mono" style={{ fontSize: '0.78rem' }}>
                    {alt.host || alt.user || '—'}
                  </td>
                  <td>
                    <span className="badge badge-info">{alt.category}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
