import React, { useState, useEffect, useCallback } from 'react';
import {
  SearchCode,
  Clock,
  FileText,
  Copy,
  Check,
  Layers,
  Cpu,
  ShieldCheck,
  Terminal,
  Activity,
  RefreshCw,
} from 'lucide-react';
import { api } from '../api/client';
import SeverityBadge from '../components/SeverityBadge';
import StatusBadge from '../components/StatusBadge';
import SimBanner from '../components/SimBanner';
import Modal from '../components/Modal';

export default function InvestigationPage({ incidentId, onSelectIncident, showToast, onNavigate, onRefreshGlobal }) {
  const [incidentsList, setIncidentsList] = useState([]);
  const [currentId, setCurrentId] = useState(incidentId || 'INC-2026-084');
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [relatedAlerts, setRelatedAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('findings'); // findings, timeline, evidence, alerts

  const [copiedValue, setCopiedValue] = useState(null);
  const [selectedAlertForModal, setSelectedAlertForModal] = useState(null);
  const [swarmResult, setSwarmResult] = useState(null);
  const [runningSwarm, setRunningSwarm] = useState(false);

  // Fetch all incidents for switcher dropdown
  useEffect(() => {
    const loadList = async () => {
      try {
        const res = await api.getIncidents({ limit: 20 });
        setIncidentsList(res.items || []);
      } catch (err) {
        console.error('Error loading incidents list:', err);
      }
    };
    loadList();
  }, [currentId]);

  // Load selected incident details and related alerts
  const loadIncidentDetail = useCallback(async (idToLoad) => {
    try {
      setLoading(true);
      const detail = await api.getIncidentDetail(idToLoad);
      setIncidentDetail(detail);

      const alertsRes = await api.getAlerts({ incident_id: idToLoad, limit: 50 });
      setRelatedAlerts(alertsRes.items || []);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
      showToast('Error loading incident: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    if (currentId) {
      const timer = window.setTimeout(() => loadIncidentDetail(currentId), 0);
      return () => window.clearTimeout(timer);
    }
  }, [currentId, loadIncidentDetail]);

  const handleCopy = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedValue(text);
    showToast('Copied to clipboard!');
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleStatusChange = async (newStatus) => {
    try {
      const updated = await api.updateIncident(currentId, { status: newStatus });
      setIncidentDetail(updated);
      showToast(`Incident status updated to ${newStatus}`);
    } catch (err) {
      showToast('Failed to update status: ' + err.message);
    }
  };

  const handleRunSwarm = async () => {
    try {
      setRunningSwarm(true);
      const result = await api.runSwarmInvestigation(currentId);
      setSwarmResult(result);
      await loadIncidentDetail(currentId);
      if (onRefreshGlobal) await onRefreshGlobal();
      showToast(`Four agents completed: risk ${result.risk_score}/100; ${result.approval_proposals.length} approval proposals.`);
    } catch (err) {
      showToast('Swarm investigation failed: ' + err.message);
    } finally {
      setRunningSwarm(false);
    }
  };

  return (
    <div className="page-body">
      <SimBanner />

      {/* Incident Switcher & Header */}
      <div className="page-header" style={{ marginBottom: '1.25rem' }}>
        <div className="page-title-group">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <h2>Investigation Console</h2>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Target:</span>
              <select
                className="filter-select mono"
                style={{ fontWeight: 700 }}
                value={currentId}
                onChange={(e) => {
                  setCurrentId(e.target.value);
                  if (onSelectIncident) onSelectIncident(e.target.value);
                }}
              >
                {incidentsList.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    {inc.id} — {inc.title.substring(0, 45)}...
                  </option>
                ))}
              </select>
            </div>
          </div>
          <p>
            Detailed event timeline, correlated telemetry evidence, and deterministic swarm findings.
          </p>
        </div>

        {incidentDetail && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button className="btn btn-primary btn-sm" onClick={handleRunSwarm} disabled={runningSwarm}>
              <RefreshCw size={14} className={runningSwarm ? 'spin-animation' : ''} />
              {runningSwarm ? 'Investigating…' : 'Run four-agent investigation'}
            </button>
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>Workflow State:</span>
            <select
              className="filter-select"
              value={incidentDetail.status}
              onChange={(e) => handleStatusChange(e.target.value)}
            >
              <option value="OPEN">OPEN</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="AWAITING_REVIEW">AWAITING REVIEW</option>
              <option value="CONTAINED">CONTAINED</option>
              <option value="RESOLVED">RESOLVED</option>
            </select>
          </div>
        )}
      </div>

      {loading || !incidentDetail ? (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Loading incident investigation data...
        </div>
      ) : (
        <>
          {swarmResult && (
            <div className="card" style={{ marginBottom: '1rem', borderLeft: '4px solid #0f766e' }}>
              <div className="card-header">
                <span className="card-title"><Activity size={18} color="#0f766e" /> Latest swarm run · {swarmResult.severity} · risk {swarmResult.risk_score}/100</span>
                <span className="badge badge-info">SIMULATED</span>
              </div>
              <div className="card-body">
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.75rem' }}>
                  {Object.entries(swarmResult.agents).map(([key, agent]) => (
                    <div key={key} style={{ padding: '0.85rem', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-md)' }}>
                      <strong>{agent.agent_name}</strong>
                      <p style={{ marginTop: '0.35rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{agent.summary}</p>
                    </div>
                  ))}
                </div>
                <p style={{ marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  {swarmResult.evidence.length} evidence items · {swarmResult.findings.length} findings · {swarmResult.approval_proposals.length} new proposals sent to analyst approval.
                </p>
                {swarmResult.approval_proposals.length > 0 && (
                  <div style={{ marginTop: '0.75rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.8rem' }}>{swarmResult.approval_proposals.map((item) => `${item.action_type}: ${item.target}`).join(' · ')}</span>
                    <button className="btn btn-outline btn-sm" onClick={() => onNavigate?.('approvals')}>Review proposals</button>
                  </div>
                )}
              </div>
            </div>
          )}
          {/* Incident Hero Card */}
          <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '4px solid var(--primary)' }}>
            <div className="card-body">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem', marginBottom: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.35rem' }}>
                    <span className="mono" style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--primary)' }}>
                      {incidentDetail.id}
                    </span>
                    <SeverityBadge severity={incidentDetail.severity} />
                    <StatusBadge status={incidentDetail.status} />
                  </div>
                  <h3 style={{ fontSize: '1.35rem', fontWeight: 800, color: 'var(--text-primary)', marginBottom: '0.35rem' }}>
                    {incidentDetail.title}
                  </h3>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', maxWidth: '850px' }}>
                    {incidentDetail.summary}
                  </p>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
                  <div style={{ textAlign: 'right' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                      Risk Assessment Score
                    </span>
                    <div className="risk-meter" style={{ justifyContent: 'flex-end', marginTop: '2px' }}>
                      <div className="risk-bar-track" style={{ width: '100px', height: '12px' }}>
                        <div
                          className="risk-bar-fill"
                          style={{
                            width: `${incidentDetail.risk_score}%`,
                            backgroundColor:
                              incidentDetail.risk_score >= 80 ? '#dc2626' : incidentDetail.risk_score >= 50 ? '#d97706' : '#16a34a',
                          }}
                        ></div>
                      </div>
                      <span style={{ fontWeight: 800, fontSize: '1.1rem' }}>{incidentDetail.risk_score}/100</span>
                    </div>
                  </div>

                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                    Lead: <strong>{incidentDetail.lead_analyst}</strong>
                  </div>
                </div>
              </div>

              {/* Asset Pills & Vector */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.8rem' }}>
                <span style={{ fontWeight: 700, color: 'var(--text-muted)' }}>AFFECTED ASSETS:</span>
                {(incidentDetail.affected_assets || []).map((asset, idx) => (
                  <span
                    key={idx}
                    className="mono"
                    style={{
                      background: 'var(--bg-surface-subtle)',
                      padding: '0.2rem 0.5rem',
                      borderRadius: 'var(--radius-sm)',
                      fontWeight: 600,
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    {asset}
                  </span>
                ))}
                <span style={{ marginLeft: 'auto', color: 'var(--text-muted)' }}>
                  Vector: <strong style={{ color: 'var(--text-primary)' }}>{incidentDetail.attack_vector}</strong>
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
            <button
              className={`btn ${activeTab === 'findings' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActiveTab('findings')}
            >
              <FileText size={15} />
              <span>Swarm Findings & Hypothesis</span>
            </button>
            <button
              className={`btn ${activeTab === 'timeline' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActiveTab('timeline')}
            >
              <Clock size={15} />
              <span>Event Timeline ({(incidentDetail.timeline_events || []).length})</span>
            </button>
            <button
              className={`btn ${activeTab === 'evidence' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActiveTab('evidence')}
            >
              <SearchCode size={15} />
              <span>Correlated Evidence ({(incidentDetail.evidence_items || []).length})</span>
            </button>
            <button
              className={`btn ${activeTab === 'alerts' ? 'btn-primary' : 'btn-outline'}`}
              onClick={() => setActiveTab('alerts')}
            >
              <Terminal size={15} />
              <span>Related Alerts ({relatedAlerts.length})</span>
            </button>
          </div>

          {/* TAB 1: FINDINGS & HYPOTHESIS */}
          {activeTab === 'findings' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              {/* Hypothesis Box */}
              {incidentDetail.investigation && (
                <div className="card" style={{ marginBottom: 0 }}>
                  <div className="card-header" style={{ background: '#f8fafc' }}>
                    <span className="card-title">
                      <Cpu size={18} color="var(--primary)" />
                      Working Incident Hypothesis (Deterministic Correlation)
                    </span>
                    <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#0369a1', background: '#e0f2fe', padding: '0.2rem 0.6rem', borderRadius: 'var(--radius-full)' }}>
                      Confidence: {Math.round(incidentDetail.investigation.confidence_score * 100)}%
                    </span>
                  </div>
                  <div className="card-body">
                    <p style={{ fontSize: '0.95rem', lineHeight: '1.6', color: 'var(--text-primary)', marginBottom: '1rem' }}>
                      {incidentDetail.investigation.hypothesis}
                    </p>
                    <div style={{ background: 'var(--bg-surface-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-md)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      <strong>Executive Summary:</strong> {incidentDetail.investigation.summary}
                    </div>
                  </div>
                </div>
              )}

              {/* Observable Findings Grid */}
              {incidentDetail.investigation?.findings?.length > 0 && (
                <div className="card" style={{ marginBottom: 0 }}>
                  <div className="card-header">
                    <span className="card-title">
                      <Activity size={18} color="#047857" />
                      Key Observable Findings
                    </span>
                  </div>
                  <div className="card-body">
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                      {incidentDetail.investigation.findings.map((finding, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '1rem',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                            background: 'white',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                            <span className="mono" style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--primary)' }}>
                              {finding.finding_id || `FIND-0${idx + 1}`}
                            </span>
                            {finding.severity && <SeverityBadge severity={finding.severity} />}
                          </div>
                          <h4 style={{ fontSize: '0.95rem', fontWeight: 700, marginBottom: '0.35rem' }}>
                            {finding.title || finding.category}
                          </h4>
                          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                            {finding.description || finding.observation}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Recommended Containment Actions */}
              {incidentDetail.investigation?.recommended_containment?.length > 0 && (
                <div className="card" style={{ marginBottom: 0 }}>
                  <div className="card-header">
                    <span className="card-title">
                      <ShieldCheck size={18} color="#ea580c" />
                      Recommended Containment Actions (Pending Approval)
                    </span>
                  </div>
                  <div className="card-body">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {incidentDetail.investigation.recommended_containment.map((rec, idx) => (
                        <div
                          key={idx}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            padding: '0.85rem',
                            border: '1px solid var(--border-subtle)',
                            borderRadius: 'var(--radius-md)',
                            background: 'white',
                            flexWrap: 'wrap',
                            gap: '0.75rem',
                          }}
                        >
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                              <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>{rec.action}</span>
                              <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--primary)', fontWeight: 600 }}>
                                🎯 {rec.target}
                              </span>
                            </div>
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                              {rec.detail || rec.reason}
                            </div>
                          </div>
                          <span className="badge badge-high">{rec.priority}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK Framework Mapping */}
              <div className="card" style={{ marginBottom: 0 }}>
                <div className="card-header">
                  <span className="card-title">
                    <Layers size={18} color="#6d28d9" />
                    MITRE ATT&CK Framework Mapping
                  </span>
                </div>
                <div className="card-body">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem' }}>
                    {(incidentDetail.mitre_tactics || []).map((tactic, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: '#f5f3ff',
                          border: '1px solid #ddd6fe',
                          color: '#5b21b6',
                          padding: '0.4rem 0.8rem',
                          borderRadius: 'var(--radius-md)',
                          fontSize: '0.82rem',
                          fontWeight: 600,
                        }}
                      >
                        {tactic}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: EVENT TIMELINE */}
          {activeTab === 'timeline' && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">
                  <Clock size={18} color="var(--primary)" />
                  Attack Progression Timeline
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Chronological Sequence</span>
              </div>
              <div className="card-body">
                {(incidentDetail.timeline_events || []).length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No timeline events recorded for this incident.
                  </div>
                ) : (
                  <div className="timeline-list">
                    {incidentDetail.timeline_events.map((evt) => (
                      <div key={evt.id} className="timeline-item">
                        <div className="timeline-dot"></div>
                        <div className="timeline-card">
                          <div className="timeline-meta">
                            <span className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {new Date(evt.timestamp).toUTCString().replace('GMT', 'UTC')}
                            </span>
                            <span className="badge badge-info">{evt.event_type}</span>
                            <SeverityBadge severity={evt.severity} />
                            {evt.mitre_technique && (
                              <span className="badge badge-awaiting">{evt.mitre_technique}</span>
                            )}
                            <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                              Actor: {evt.actor}
                            </span>
                          </div>
                          <div className="timeline-title">{evt.title}</div>
                          <div className="timeline-desc">{evt.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: CORRELATED EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">
                  <SearchCode size={18} color="var(--primary)" />
                  Correlated Evidence & Forensic Artifacts
                </span>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Validated Indicators & Observables
                </span>
              </div>
              <div className="card-body">
                {(incidentDetail.evidence_items || []).length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No forensic evidence items mapped to this incident.
                  </div>
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
                    {incidentDetail.evidence_items.map((item) => (
                      <div
                        key={item.id}
                        style={{
                          border: '1px solid var(--border-subtle)',
                          borderRadius: 'var(--radius-md)',
                          padding: '1rem',
                          background: 'white',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: '0.5rem',
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span className="badge badge-info">{item.evidence_type}</span>
                          <span
                            className="badge"
                            style={{
                              backgroundColor:
                                item.verdict === 'MALICIOUS'
                                  ? '#fee2e2'
                                  : item.verdict === 'SUSPICIOUS'
                                  ? '#fef3c7'
                                  : '#f0fdf4',
                              color:
                                item.verdict === 'MALICIOUS'
                                  ? '#b91c1c'
                                  : item.verdict === 'SUSPICIOUS'
                                  ? '#b45309'
                                  : '#15803d',
                            }}
                          >
                            {item.verdict}
                          </span>
                        </div>

                        <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>{item.label}</div>

                        <div
                          className="mono"
                          style={{
                            background: '#f8fafc',
                            padding: '0.5rem',
                            borderRadius: 'var(--radius-sm)',
                            border: '1px solid var(--border-subtle)',
                            fontSize: '0.78rem',
                            wordBreak: 'break-all',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'space-between',
                            gap: '0.5rem',
                          }}
                        >
                          <span>{item.value}</span>
                          <button
                            className="btn btn-outline btn-sm"
                            style={{ padding: '0.15rem 0.35rem', border: 'none' }}
                            onClick={() => handleCopy(item.value)}
                            title="Copy Value"
                          >
                            {copiedValue === item.value ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                          </button>
                        </div>

                        {item.notes && (
                          <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                            {item.notes}
                          </div>
                        )}

                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 'auto', paddingTop: '0.35rem', borderTop: '1px solid #f1f5f9' }}>
                          Source: {item.source}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: RELATED ALERTS */}
          {activeTab === 'alerts' && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">
                  <Terminal size={18} color="var(--primary)" />
                  Correlated Telemetry Alerts ({relatedAlerts.length})
                </span>
              </div>
              <div className="table-responsive">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Alert ID</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Title</th>
                      <th>Sensor</th>
                      <th>Host / User</th>
                      <th>Timestamp</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {relatedAlerts.length === 0 ? (
                      <tr>
                        <td colSpan="8" style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                          No alerts linked to this incident.
                        </td>
                      </tr>
                    ) : (
                      relatedAlerts.map((alt) => (
                        <tr key={alt.id}>
                          <td className="mono" style={{ fontWeight: 700, color: 'var(--primary)' }}>{alt.id}</td>
                          <td><SeverityBadge severity={alt.severity} /></td>
                          <td><StatusBadge status={alt.status} /></td>
                          <td style={{ fontWeight: 600 }}>{alt.title}</td>
                          <td style={{ fontSize: '0.8rem' }}>{alt.source}</td>
                          <td className="mono" style={{ fontSize: '0.78rem' }}>{alt.host || alt.user || '—'}</td>
                          <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            {new Date(alt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </td>
                          <td>
                            <button
                              className="btn btn-outline btn-sm"
                              onClick={() => setSelectedAlertForModal(alt)}
                            >
                              Inspect
                            </button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* Raw Payload Modal for Related Alerts */}
      {selectedAlertForModal && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedAlertForModal(null)}
          title={`Raw Telemetry: ${selectedAlertForModal.id}`}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <SeverityBadge severity={selectedAlertForModal.severity} />
              <StatusBadge status={selectedAlertForModal.status} />
            </div>
            <h4 style={{ fontWeight: 700 }}>{selectedAlertForModal.title}</h4>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{selectedAlertForModal.description}</p>
            <pre
              className="mono"
              style={{
                background: '#0f172a',
                color: '#38bdf8',
                padding: '0.85rem',
                borderRadius: 'var(--radius-md)',
                fontSize: '0.75rem',
                overflowX: 'auto',
                maxHeight: '250px',
              }}
            >
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(selectedAlertForModal.raw_payload), null, 2);
    } catch {
                  return selectedAlertForModal.raw_payload;
                }
              })()}
            </pre>
          </div>
        </Modal>
      )}
    </div>
  );
}
