import React, { useState, useEffect, useCallback } from 'react';
import { Search, Eye, RefreshCw, ExternalLink } from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import Modal from '../components/Modal';
import SimBanner from '../components/SimBanner';

export default function AlertsPage({ onSelectIncident, showToast }) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [status, setStatus] = useState('ALL');
  const [source, setSource] = useState('ALL');

  // Selected alert for modal inspection
  const [selectedAlert, setSelectedAlert] = useState(null);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getAlerts({
        search: search || undefined,
        severity: severity !== 'ALL' ? severity : undefined,
        status: status !== 'ALL' ? status : undefined,
        source: source !== 'ALL' ? source : undefined,
        limit: 100,
      });
      setAlerts(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error('Failed to load alerts:', err);
      showToast('Error loading alerts: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [search, severity, status, source, showToast]);

  useEffect(() => {
    const timer = window.setTimeout(fetchAlerts, 0);
    return () => window.clearTimeout(timer);
  }, [fetchAlerts]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchAlerts();
  };

  const handleStatusChange = async (alertId, newStatus) => {
    try {
      await api.updateAlert(alertId, { status: newStatus });
      showToast(`Alert ${alertId} updated to ${newStatus}`);
      fetchAlerts();
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert({ ...selectedAlert, status: newStatus });
      }
    } catch (err) {
      showToast('Failed to update alert: ' + err.message);
    }
  };

  return (
    <div className="page-body">
      <SimBanner />

      <div className="page-header">
        <div className="page-title-group">
          <h2>Security Telemetry & Alerts ({total})</h2>
          <p>
            Real-time ingested telemetry from EDR sensors, network intrusion detection systems, and identity providers.
          </p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={fetchAlerts} disabled={loading}>
          <RefreshCw size={13} className={loading ? 'spin-animation' : ''} />
          Refresh Feed
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
              placeholder="Search by title, host, user, IP, or keywords..."
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
            <option value="INFORMATIONAL">Informational</option>
          </select>

          <select
            className="filter-select"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="ALL">Status: All</option>
            <option value="NEW">New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="ESCALATED">Escalated</option>
            <option value="RESOLVED">Resolved</option>
          </select>

          <select
            className="filter-select"
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="ALL">Sensor: All Sources</option>
            <option value="CrowdStrike">CrowdStrike EDR</option>
            <option value="Sysmon">Sysmon EDR</option>
            <option value="Suricata">Suricata NIDS</option>
            <option value="Okta">Okta Identity</option>
            <option value="Zeek">Zeek Sensor</option>
            <option value="Snort">Snort NIDS</option>
          </select>

          <button type="submit" className="btn btn-primary">
            Filter
          </button>
        </form>
      </div>

      {/* Alerts Table */}
      <div className="card">
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Alert ID</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Timestamp (UTC)</th>
                <th>Alert Title & Description</th>
                <th>Source Sensor</th>
                <th>Host / User</th>
                <th>Network Context</th>
                <th>Incident</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="10" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    Loading security alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan="10" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    No security alerts found matching the active filters.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td className="mono" style={{ fontWeight: 700, color: 'var(--primary)' }}>
                      {alert.id}
                    </td>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <StatusBadge status={alert.status} />
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                      {new Date(alert.timestamp).toISOString().replace('T', ' ').substring(0, 19)}
                    </td>
                    <td style={{ maxWidth: '320px' }}>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{alert.title}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {alert.description}
                      </div>
                    </td>
                    <td style={{ fontSize: '0.8rem' }}>{alert.source}</td>
                    <td className="mono" style={{ fontSize: '0.8rem' }}>
                      {alert.host && <div>💻 {alert.host}</div>}
                      {alert.user && <div>👤 {alert.user}</div>}
                      {!alert.host && !alert.user && <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {alert.source_ip && <div>Src: {alert.source_ip}</div>}
                      {alert.destination_ip && <div>Dst: {alert.destination_ip}</div>}
                      {!alert.source_ip && !alert.destination_ip && <span style={{ color: 'var(--text-muted)' }}>—</span>}
                    </td>
                    <td>
                      {alert.incident_id ? (
                        <button
                          className="btn btn-outline btn-sm"
                          style={{ fontSize: '0.72rem', padding: '0.2rem 0.5rem', color: 'var(--primary)' }}
                          onClick={() => onSelectIncident(alert.incident_id)}
                        >
                          {alert.incident_id} <ExternalLink size={10} />
                        </button>
                      ) : (
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Uncorrelated</span>
                      )}
                    </td>
                    <td>
                      <button
                        className="btn btn-outline btn-sm"
                        onClick={() => setSelectedAlert(alert)}
                        title="View Full Telemetry"
                      >
                        <Eye size={13} />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Detail & Raw Payload Modal */}
      {selectedAlert && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedAlert(null)}
          title={`Alert Inspection: ${selectedAlert.id}`}
          footer={
            <div style={{ display: 'flex', gap: '0.5rem', width: '100%', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 600 }}>Update Status:</span>
                <select
                  className="filter-select"
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                  value={selectedAlert.status}
                  onChange={(e) => handleStatusChange(selectedAlert.id, e.target.value)}
                >
                  <option value="NEW">NEW</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="ESCALATED">ESCALATED</option>
                  <option value="RESOLVED">RESOLVED</option>
                </select>
              </div>

              {selectedAlert.incident_id ? (
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => {
                    const incId = selectedAlert.incident_id;
                    setSelectedAlert(null);
                    onSelectIncident(incId);
                  }}
                >
                  Go to Incident {selectedAlert.incident_id}
                </button>
              ) : (
                <button className="btn btn-outline btn-sm" onClick={() => setSelectedAlert(null)}>
                  Close
                </button>
              )}
            </div>
          }
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
              <SeverityBadge severity={selectedAlert.severity} />
              <StatusBadge status={selectedAlert.status} />
              <span className="badge badge-info">{selectedAlert.category}</span>
            </div>

            <div>
              <h4 style={{ fontSize: '1.05rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                {selectedAlert.title}
              </h4>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                {selectedAlert.description}
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', background: 'var(--bg-surface-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-md)', fontSize: '0.8rem' }}>
              <div>
                <strong>Sensor Source:</strong> {selectedAlert.source}
              </div>
              <div>
                <strong>Timestamp:</strong> {new Date(selectedAlert.timestamp).toUTCString()}
              </div>
              <div>
                <strong>Affected Host:</strong> {selectedAlert.host || 'N/A'}
              </div>
              <div>
                <strong>Affected User:</strong> {selectedAlert.user || 'N/A'}
              </div>
              <div>
                <strong>Source IP:</strong> {selectedAlert.source_ip || 'N/A'}
              </div>
              <div>
                <strong>Destination IP:</strong> {selectedAlert.destination_ip || 'N/A'}
              </div>
            </div>

            {selectedAlert.raw_payload && (
              <div>
                <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                  Raw Telemetry Payload (JSON)
                </div>
                <pre
                  className="mono"
                  style={{
                    background: '#0f172a',
                    color: '#38bdf8',
                    padding: '0.85rem',
                    borderRadius: 'var(--radius-md)',
                    fontSize: '0.75rem',
                    overflowX: 'auto',
                    maxHeight: '220px',
                  }}
                >
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(selectedAlert.raw_payload), null, 2);
    } catch {
                      return selectedAlert.raw_payload;
                    }
                  })()}
                </pre>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}
