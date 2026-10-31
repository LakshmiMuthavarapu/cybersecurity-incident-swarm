import React, { useState, useEffect, useCallback } from 'react';
import { Search, Plus, CheckCircle, RefreshCw, Copy, Check } from 'lucide-react';
import { api } from '../api/client';
import StatusBadge from '../components/StatusBadge';
import SimBanner from '../components/SimBanner';
import Modal from '../components/Modal';

export default function ThreatIntelPage({ showToast }) {
  const [indicators, setIndicators] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState('');
  const [indicatorType, setIndicatorType] = useState('ALL');
  const [reputation, setReputation] = useState('ALL');
  const [verificationStatus, setVerificationStatus] = useState('ALL');

  // Copy helper
  const [copiedValue, setCopiedValue] = useState(null);

  // Add IoC Modal state
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [newIoc, setNewIoc] = useState({
    indicator_type: 'IP',
    value: '',
    reputation: 'SUSPICIOUS',
    threat_actor: '',
    confidence: 85,
    verification_status: 'PENDING_REVIEW',
    tags: '',
    description: '',
  });

  const fetchThreatIntel = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getThreatIntel({
        search: search || undefined,
        indicator_type: indicatorType !== 'ALL' ? indicatorType : undefined,
        reputation: reputation !== 'ALL' ? reputation : undefined,
        verification_status: verificationStatus !== 'ALL' ? verificationStatus : undefined,
      });
      setIndicators(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error('Error fetching threat indicators:', err);
      showToast('Error loading threat indicators: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, [search, indicatorType, reputation, verificationStatus, showToast]);

  useEffect(() => {
    const timer = window.setTimeout(fetchThreatIntel, 0);
    return () => window.clearTimeout(timer);
  }, [fetchThreatIntel]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    fetchThreatIntel();
  };

  const handleCopy = (val) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    showToast('IoC copied to clipboard!');
    setTimeout(() => setCopiedValue(null), 2000);
  };

  const handleVerifyIoC = async (iocId) => {
    try {
      await api.updateThreatIndicator(iocId, {
        verification_status: 'VERIFIED',
        confidence: 95,
      });
      showToast(`IoC ${iocId} verified by Analyst Alex Rivera.`);
      fetchThreatIntel();
    } catch (err) {
      showToast('Failed to verify IoC: ' + err.message);
    }
  };

  const handleAddSubmit = async (e) => {
    e.preventDefault();
    if (!newIoc.value.trim()) {
      showToast('Please enter an indicator value.');
      return;
    }

    try {
      const tagsArray = newIoc.tags
        .split(',')
        .map((t) => t.trim())
        .filter((t) => t.length > 0);

      await api.addThreatIndicator({
        indicator_type: newIoc.indicator_type,
        value: newIoc.value.trim(),
        reputation: newIoc.reputation,
        threat_actor: newIoc.threat_actor || 'Unknown Simulated Actor',
        confidence: Number(newIoc.confidence) || 80,
        verification_status: newIoc.verification_status,
        tags: tagsArray,
        description: newIoc.description || 'Simulated threat intelligence indicator.',
        is_simulated: true,
      });

      showToast('New simulated IoC added successfully!');
      setIsAddModalOpen(false);
      setNewIoc({
        indicator_type: 'IP',
        value: '',
        reputation: 'SUSPICIOUS',
        threat_actor: '',
        confidence: 85,
        verification_status: 'PENDING_REVIEW',
        tags: '',
        description: '',
      });
      fetchThreatIntel();
    } catch (err) {
      showToast('Error adding indicator: ' + err.message);
    }
  };

  return (
    <div className="page-body">
      <SimBanner />

      <div className="page-header">
        <div className="page-title-group">
          <h2>Threat Intelligence & Indicators of Compromise ({total})</h2>
          <p>
            Repository of simulated network, file, and domain indicators enriched with adversary attribution and confidence ratings.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-outline btn-sm" onClick={fetchThreatIntel} disabled={loading}>
            <RefreshCw size={13} className={loading ? 'spin-animation' : ''} />
            Refresh
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setIsAddModalOpen(true)}>
            <Plus size={14} />
            Add Simulated IoC
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="card" style={{ padding: '1rem', marginBottom: '1.25rem' }}>
        <form onSubmit={handleSearchSubmit} className="filter-bar" style={{ margin: 0 }}>
          <div className="search-box">
            <Search size={16} className="search-icon" />
            <input
              type="text"
              className="search-input"
              placeholder="Search IoC value, threat actor, or tag..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={indicatorType}
            onChange={(e) => setIndicatorType(e.target.value)}
          >
            <option value="ALL">Type: All</option>
            <option value="IP">IP Address</option>
            <option value="DOMAIN">Domain</option>
            <option value="SHA256">SHA256 Hash</option>
            <option value="MD5">MD5 Hash</option>
            <option value="CVE">CVE Identifier</option>
          </select>

          <select
            className="filter-select"
            value={verificationStatus}
            onChange={(e) => setVerificationStatus(e.target.value)}
          >
            <option value="ALL">Status: All</option>
            <option value="VERIFIED">Verified</option>
            <option value="PENDING_REVIEW">Pending Review</option>
            <option value="UNVERIFIED">Unverified</option>
          </select>

          <select
            className="filter-select"
            value={reputation}
            onChange={(e) => setReputation(e.target.value)}
          >
            <option value="ALL">Reputation: All</option>
            <option value="MALICIOUS">Malicious</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="BENIGN">Benign</option>
          </select>

          <button type="submit" className="btn btn-primary">
            Filter
          </button>
        </form>
      </div>

      {/* Threat Indicators Table */}
      <div className="card">
        <div className="table-responsive">
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Indicator Value</th>
                <th>Reputation</th>
                <th>Confidence</th>
                <th>Threat Actor / Attribution</th>
                <th>Verification Status</th>
                <th>Tags</th>
                <th>Last Observed</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    Loading threat intelligence vault...
                  </td>
                </tr>
              ) : indicators.length === 0 ? (
                <tr>
                  <td colSpan="9" style={{ textAlign: 'center', padding: '2.5rem', color: 'var(--text-muted)' }}>
                    No threat indicators found matching current filters.
                  </td>
                </tr>
              ) : (
                indicators.map((ti) => (
                  <tr key={ti.id}>
                    <td>
                      <span className="badge badge-info">{ti.indicator_type}</span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span className="mono" style={{ fontWeight: 600, fontSize: '0.82rem' }}>
                          {ti.value}
                        </span>
                        <button
                          className="btn btn-outline btn-sm"
                          style={{ padding: '0.15rem 0.35rem', border: 'none' }}
                          onClick={() => handleCopy(ti.value)}
                          title="Copy IoC"
                        >
                          {copiedValue === ti.value ? <Check size={12} color="#16a34a" /> : <Copy size={12} />}
                        </button>
                      </div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                        {ti.description}
                      </div>
                    </td>
                    <td>
                      <span
                        className="badge"
                        style={{
                          backgroundColor:
                            ti.reputation === 'MALICIOUS'
                              ? '#fee2e2'
                              : ti.reputation === 'SUSPICIOUS'
                              ? '#fef3c7'
                              : '#f0fdf4',
                          color:
                            ti.reputation === 'MALICIOUS'
                              ? '#b91c1c'
                              : ti.reputation === 'SUSPICIOUS'
                              ? '#b45309'
                              : '#15803d',
                        }}
                      >
                        {ti.reputation}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <div className="risk-bar-track" style={{ width: '50px', height: '6px' }}>
                          <div
                            className="risk-bar-fill"
                            style={{
                              width: `${ti.confidence}%`,
                              backgroundColor: ti.confidence >= 80 ? '#dc2626' : '#d97706',
                            }}
                          ></div>
                        </div>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700 }}>{ti.confidence}%</span>
                      </div>
                    </td>
                    <td style={{ fontSize: '0.8rem', fontWeight: 600 }}>{ti.threat_actor || 'Unknown'}</td>
                    <td>
                      <StatusBadge status={ti.verification_status} />
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
                        {(ti.tags || []).map((tag, idx) => (
                          <span
                            key={idx}
                            style={{
                              fontSize: '0.7rem',
                              background: '#f1f5f9',
                              padding: '0.15rem 0.4rem',
                              borderRadius: 'var(--radius-sm)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {new Date(ti.last_seen).toISOString().split('T')[0]}
                    </td>
                    <td>
                      {ti.verification_status !== 'VERIFIED' ? (
                        <button
                          className="btn btn-outline btn-sm"
                          style={{ color: '#16a34a', borderColor: '#bbf7d0', fontSize: '0.75rem' }}
                          onClick={() => handleVerifyIoC(ti.id)}
                          title="Verify indicator and elevate confidence"
                        >
                          <CheckCircle size={12} />
                          Verify
                        </button>
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: '#16a34a', fontWeight: 600 }}>
                          ✓ Confirmed
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Simulated IoC Modal */}
      <Modal
        isOpen={isAddModalOpen}
        onClose={() => setIsAddModalOpen(false)}
        title="Add Simulated Threat Indicator (IoC)"
        footer={
          <>
            <button className="btn btn-outline" onClick={() => setIsAddModalOpen(false)}>
              Cancel
            </button>
            <button className="btn btn-primary" onClick={handleAddSubmit}>
              Save Indicator
            </button>
          </>
        }
      >
        <form onSubmit={handleAddSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
              Indicator Type
            </label>
            <select
              className="filter-select"
              style={{ width: '100%' }}
              value={newIoc.indicator_type}
              onChange={(e) => setNewIoc({ ...newIoc, indicator_type: e.target.value })}
            >
              <option value="IP">IP Address</option>
              <option value="DOMAIN">Domain Name</option>
              <option value="SHA256">SHA256 Hash</option>
              <option value="MD5">MD5 Hash</option>
              <option value="CVE">CVE Identifier</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
              Indicator Value *
            </label>
            <input
              type="text"
              className="search-input"
              placeholder="e.g. 198.51.100.99 or c2-malware[.]xyz"
              value={newIoc.value}
              onChange={(e) => setNewIoc({ ...newIoc, value: e.target.value })}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                Reputation
              </label>
              <select
                className="filter-select"
                style={{ width: '100%' }}
                value={newIoc.reputation}
                onChange={(e) => setNewIoc({ ...newIoc, reputation: e.target.value })}
              >
                <option value="MALICIOUS">Malicious</option>
                <option value="SUSPICIOUS">Suspicious</option>
                <option value="BENIGN">Benign</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
                Confidence Score ({newIoc.confidence}%)
              </label>
              <input
                type="range"
                min="10"
                max="100"
                value={newIoc.confidence}
                onChange={(e) => setNewIoc({ ...newIoc, confidence: e.target.value })}
                style={{ width: '100%', marginTop: '8px' }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
              Threat Actor / Campaign
            </label>
            <input
              type="text"
              className="search-input"
              placeholder="e.g. Simulated Cobalt Strike Beaconer"
              value={newIoc.threat_actor}
              onChange={(e) => setNewIoc({ ...newIoc, threat_actor: e.target.value })}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
              Tags (comma separated)
            </label>
            <input
              type="text"
              className="search-input"
              placeholder="e.g. C2, Spearphishing, Macro"
              value={newIoc.tags}
              onChange={(e) => setNewIoc({ ...newIoc, tags: e.target.value })}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.8rem', fontWeight: 600, display: 'block', marginBottom: '4px' }}>
              Description & Context
            </label>
            <textarea
              className="search-input"
              style={{ minHeight: '60px' }}
              placeholder="Observed communication pattern or source notes..."
              value={newIoc.description}
              onChange={(e) => setNewIoc({ ...newIoc, description: e.target.value })}
            />
          </div>
        </form>
      </Modal>
    </div>
  );
}
