import React, { useState, useEffect, useCallback } from 'react';
import { Search, RefreshCw, ArrowRight } from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import SimBanner from '../components/SimBanner';

export default function IncidentsPage({ onSelectIncident, showToast }) {
  const [incidents, setIncidents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ALL');

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getIncidents({
        search: search || undefined,
        severity: severity !== 'ALL' ? severity : undefined,
        status: status !== 'ALL' ? status : undefined,
      });
      setIncidents(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error('Failed to load incidents:', err);
      showToast('Error loading incidents: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [search, severity, status, showToast]);

  useEffect(() => {
    const timer = window.setTimeout(fetchIncidents, 0);
    return () => window.clearTimeout(timer);
  }, [fetchIncidents]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchIncidents();
  };

  return (
    <div className="page-body">
      <SimBanner />

      <div className="page-header">
        <div className="page-title-group">
          <h2>Correlated Incidents ({total})</h2>
          <p>
            Multi-stage attack clusters synthesized by the cybersecurity correlation swarm mapped to MITRE ATT&CK.
          </p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={fetchIncidents} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'spin-animation' : ''} />
          Refresh Incidents
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '1rem', marginBottom: '1.25rem' }}>
        <form onSubmit={handleSearchSubmit} className="filter-bar" style={{ margin: 0 }}>
          <div className="search-box">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search by title, attack vector, or affected asset..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="ALL">Severity: All</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            className="filter-select"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="ALL">Status: All</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="AWAITING_REVIEW">Awaiting Review</option>
            <option value="CONTAINED">Contained</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          <button type="submit" className="btn btn-primary">
            Filter
          </button>
        </form>
      </div>

      {/* Incident Cards List */}
      {loading ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Loading incident correlations...
        </div>
      ) : incidents.length === 0 ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          No security incidents found matching the specified criteria.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {incidents.map((incident) => (
            <div key={incident.id} className="card" style={{ marginBottom: 0, padding: 0 }}>
              <div
                style={{
                  padding: '1.25rem',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'flex-start',
                  flexWrap: 'wrap',
                  gap: '1rem',
                  borderBottom: '1px solid var(--border-subtle)',
                  background: incident.severity === 'CRITICAL' ? 'rgba(254, 242, 242, 0.4)' : 'transparent',
                }}
              >
                <div style={{ flex: 1, minWidth: '280px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.4rem', flexWrap: 'wrap' }}>
                    <span className="mono" style={{ fontWeight: 800, fontSize: '1rem', color: 'var(--primary)' }}>
                      {incident.id}
                    </span>
                    <SeverityBadge severity={incident.severity} />
                    <StatusBadge status={incident.status} />
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Updated {new Date(incident.updated_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>

                  <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                    {incident.title}
                  </h3>

                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                    {incident.summary}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    <span>Vector:</span>
                    <strong style={{ color: 'var(--text-primary)' }}>{incident.attack_vector}</strong>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.75rem' }}>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '2px' }}>Risk Score</div>
                    <div className="risk-meter" style={{ justifyContent: 'flex-end' }}>
                      <div className="risk-bar-track" style={{ width: '90px', height: '10px' }}>
                        <div
                          className="risk-bar-fill"
                          style={{
                            width: `${incident.risk_score}%`,
                            backgroundColor:
                              incident.risk_score >= 80 ? '#dc2626' : incident.risk_score >= 50 ? '#d97706' : '#16a34a',
                          }}
                        ></div>
                      </div>
                      <span style={{ fontWeight: 800, fontSize: '1rem' }}>{incident.risk_score}/100</span>
                    </div>
                  </div>

                  <button
                    className="btn btn-primary"
                    onClick={() => onSelectIncident(incident.id)}
                    style={{ whiteSpace: 'nowrap' }}
                  >
                    Investigate Swarm Graph <ArrowRight size={14} />
                  </button>
                </div>
              </div>

              {/* Card Footer: Affected Assets & MITRE Tags */}
              <div
                style={{
                  padding: '0.85rem 1.25rem',
                  background: 'var(--bg-surface-subtle)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '0.75rem',
                  fontSize: '0.78rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 700, color: 'var(--text-muted)' }}>AFFECTED ASSETS:</span>
                  {(incident.affected_assets || []).map((asset, idx) => (
                    <span
                      key={idx}
                      className="mono"
                      style={{
                        background: 'white',
                        border: '1px solid var(--border-subtle)',
                        padding: '0.2rem 0.5rem',
                        borderRadius: 'var(--radius-sm)',
                        fontWeight: 600,
                        color: 'var(--text-primary)',
                      }}
                    >
                      {asset}
                    </span>
                  ))}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Correlated Alerts: <strong>{incident.alert_count || 0}</strong>
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>
                    Lead: <strong>{incident.lead_analyst}</strong>
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
