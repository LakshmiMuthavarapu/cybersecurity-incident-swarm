import React, { useState, useEffect, useCallback } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import IncidentsPage from './pages/IncidentsPage';
import InvestigationPage from './pages/InvestigationPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import ApprovalsPage from './pages/ApprovalsPage';
import AuditLogsPage from './pages/AuditLogsPage';
import { api } from './api/client';

export default function App() {
  const [activePage, setActivePage] = useState('dashboard');
  const [selectedIncidentId, setSelectedIncidentId] = useState('INC-2026-084');
  const [dashboardStats, setDashboardStats] = useState(null);
  const [healthStatus, setHealthStatus] = useState(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [toasts, setToasts] = useState([]);

  // Toast notification helper
  const showToast = useCallback((message) => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, message }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 3500);
  }, []);

  // Load dashboard stats and health
  const loadGlobalData = useCallback(async () => {
    try {
      setIsRefreshing(true);
      const [statsRes, healthRes] = await Promise.all([
        api.getDashboardStats(),
        api.getHealth(),
      ]);
      setDashboardStats(statsRes);
      setHealthStatus(healthRes);
    } catch (err) {
      console.error('Failed to load global data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(loadGlobalData, 0);
    return () => window.clearTimeout(timer);
  }, [loadGlobalData]);

  const handleSelectIncident = (incId) => {
    setSelectedIncidentId(incId);
    setActivePage('investigation');
  };

  return (
    <div className="app-container">
      {/* Left Sidebar */}
      <Sidebar
        activePage={activePage}
        setActivePage={setActivePage}
        pendingApprovalsCount={dashboardStats?.pending_approvals || 0}
      />

      {/* Main Content Area */}
      <div className="main-content">
        <Navbar
          onRefresh={loadGlobalData}
          isRefreshing={isRefreshing}
          healthStatus={healthStatus}
        />

        <main>
          {activePage === 'dashboard' && (
            <DashboardPage
              stats={dashboardStats}
              onNavigate={setActivePage}
              onSelectIncident={handleSelectIncident}
            />
          )}

          {activePage === 'alerts' && (
            <AlertsPage
              onSelectIncident={handleSelectIncident}
              showToast={showToast}
            />
          )}

          {activePage === 'incidents' && (
            <IncidentsPage
              onSelectIncident={handleSelectIncident}
              showToast={showToast}
            />
          )}

          {activePage === 'investigation' && (
            <InvestigationPage
              key={selectedIncidentId}
              incidentId={selectedIncidentId}
              onSelectIncident={setSelectedIncidentId}
              showToast={showToast}
              onNavigate={setActivePage}
              onRefreshGlobal={loadGlobalData}
            />
          )}

          {activePage === 'threat-intel' && (
            <ThreatIntelPage showToast={showToast} />
          )}

          {activePage === 'approvals' && (
            <ApprovalsPage
              onSelectIncident={handleSelectIncident}
              showToast={showToast}
              onRefreshGlobal={loadGlobalData}
            />
          )}

          {activePage === 'audit-logs' && (
            <AuditLogsPage showToast={showToast} />
          )}
        </main>
      </div>

      {/* Toast Feedback Notifications */}
      {toasts.length > 0 && (
        <div className="toast-container">
          {toasts.map((t) => (
            <div key={t.id} className="toast">
              <span>🛡️</span>
              <span>{t.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
