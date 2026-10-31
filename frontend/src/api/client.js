/**
 * Centralized API client for Cybersecurity Incident Investigation Swarm.
 */

const BASE_URL = ''; // Uses relative path to leverage Vite proxy to :8000

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const response = await fetch(url, { ...options, headers });
    if (!response.ok) {
      let errorMessage = `HTTP Error ${response.status}`;
      try {
        const errorJson = await response.json();
        errorMessage = errorJson.detail || errorMessage;
      } catch {
        // Ignored
      }
      throw new Error(errorMessage);
    }
    return await response.json();
  } catch (error) {
    console.error(`API Error on ${endpoint}:`, error);
    throw error;
  }
}

export const api = {
  // Health
  getHealth: () => request('/api/health'),

  // Dashboard
  getDashboardStats: () => request('/api/dashboard/stats'),

  // Alerts
  getAlerts: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    });
    return request(`/api/alerts?${searchParams.toString()}`);
  },
  getAlertById: (id) => request(`/api/alerts/${id}`),
  updateAlert: (id, data, analyst = 'analyst.alex') =>
    request(`/api/alerts/${id}?analyst=${encodeURIComponent(analyst)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  // Incidents
  getIncidents: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    });
    return request(`/api/incidents?${searchParams.toString()}`);
  },
  getIncidentDetail: (id) => request(`/api/incidents/${id}`),
  updateIncident: (id, data, analyst = 'analyst.alex') =>
    request(`/api/incidents/${id}?analyst=${encodeURIComponent(analyst)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),
  getIncidentTimeline: (id) => request(`/api/incidents/${id}/timeline`),
  getIncidentEvidence: (id) => request(`/api/incidents/${id}/evidence`),
  getIncidentInvestigation: (id) => request(`/api/incidents/${id}/investigation`),
  runSwarmInvestigation: (id) => request(`/api/incidents/${id}/investigation/run`, { method: 'POST' }),

  // Threat Intel
  getThreatIntel: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    });
    return request(`/api/threat-intel?${searchParams.toString()}`);
  },
  addThreatIndicator: (data, analyst = 'analyst.alex') =>
    request(`/api/threat-intel?analyst=${encodeURIComponent(analyst)}`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateThreatIndicator: (id, data, analyst = 'analyst.alex') =>
    request(`/api/threat-intel/${id}?analyst=${encodeURIComponent(analyst)}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  // Approvals
  getApprovals: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    });
    return request(`/api/approvals?${searchParams.toString()}`);
  },
  submitApprovalDecision: (id, decision, analystName, reason) =>
    request(`/api/approvals/${id}/decision`, {
      method: 'POST',
      body: JSON.stringify({
        decision,
        analyst_name: analystName,
        reason,
      }),
    }),

  // Audit Logs
  getAuditLogs: (params = {}) => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, val]) => {
      if (val !== undefined && val !== null && val !== '') {
        searchParams.append(key, val);
      }
    });
    return request(`/api/audit-logs?${searchParams.toString()}`);
  },
};
