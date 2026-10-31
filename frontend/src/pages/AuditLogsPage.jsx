import React, { useState, useEffect, useCallback } from 'react';
import { Search, RefreshCw, User, Terminal } from 'lucide-react';
import { api } from '../api/client';
import SimBanner from '../components/SimBanner';

export default function AuditLogsPage({ showToast }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Filters
  const [targetType, setTargetType] = useState('ALL');
  const [actorSearch, setActorSearch] = useState('');

  const fetchAuditLogs = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getAuditLogs({
        target_type: targetType !== 'ALL' ? targetType : undefined,
        actor: actorSearch || undefined,
        limit: 150,
      });
      setLogs(res || []);
    } catch (err) {
      console.error('Error fetching audit logs:', err);
      showToast('Error loading audit trail: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [targetType, actorSearch, showToast]);

  useEffect(() => {
    const timer = window.setTimeout(fetchAuditLogs, 0);
    return () => window.clearTimeout(timer);
  }, [fetchAuditLogs]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchAuditLogs();
  };

  return (
    <div className="page-body">
      <SimBanner />

      <div className="page-header">
        <div className="page-title-group">
          <h2>SOC Investigation & Governance Audit Trail ({logs.length})</h2>
          <p>
            Immutable chronological ledger of swarm correlations, human analyst approvals, and threat modifications.
          </p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={fetchAuditLogs} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'spin-animation' : ''} />
          Refresh Ledger
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
              placeholder="Search by actor name (e.g. Alex, ContainmentAgent, System)..."
              value={actorSearch}
              onChange={(e) => setActorSearch(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={targetType}
            onChange={(e) => setTargetType(e.target.value)}
          >
            <option value="ALL">Target: All Categories</option>
            <option value="APPROVAL">Containment Approvals</option>
            <option value="INCIDENT">Incident Changes</option>
            <option value="ALERT">Alert Operations</option>
            <option value="THREAT_INTEL">Threat Intelligence</option>
            <option value="SYSTEM">System Telemetry</option>
          </select>

          <button type="submit" className="btn btn-primary">
            Filter
          </button>
        </form>
      </div>

      {/* Audit Log Table */}
      <div className="card">
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp (UTC)</th>
                <th>Audit ID</th>
                <th>Actor</th>
                <th>Action Type</th>
                <th>Target Reference</th>
                <th>Activity Audit Details</th>
                <th>Session Client IP</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    Loading SOC audit log records...
                  </td>
                </tr>
              ) : logs.length === 0 ? (
                <tr>
                  <td colSpan="7" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    No audit records match the current criteria.
                  </td>
                </tr>
              ) : (
                logs.map((log) => {
                  let actionBadgeClass = 'badge-info';
                  if (log.action.includes('APPROVED')) actionBadgeClass = 'badge-contained';
                  if (log.action.includes('REJECTED')) actionBadgeClass = 'badge-open';
                  if (log.action.includes('CREATED')) actionBadgeClass = 'badge-high';

                  return (
                    <tr key={log.id}>
                      <td className="mono" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                        {new Date(log.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                      </td>
                      <td className="mono" style={{ fontSize: '0.75rem', fontWeight: 600 }}>
                        {log.id}
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '0.82rem', fontWeight: 600 }}>
                          {log.actor.toLowerCase().includes('agent') ? (
                            <Terminal size={12} color="var(--primary)" />
                          ) : (
                            <User size={12} color="#475569" />
                          )}
                          {log.actor}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${actionBadgeClass}`}>
                          {log.action}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--primary)' }}>
                        {log.target_type}: {log.target_id}
                      </td>
                      <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '420px' }}>
                        {log.details}
                      </td>
                      <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {log.client_ip}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
