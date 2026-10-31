import React from 'react';
import { AlertTriangle } from 'lucide-react';

export default function SimBanner({ customText }) {
  return (
    <div className="sim-notice-banner">
      <AlertTriangle size={20} className="sim-notice-icon" />
      <div className="sim-notice-content">
        <h4>SIMULATION ENVIRONMENT — SYNTHETIC DATA & MOCK CONTAINMENT</h4>
        <p>
          {customText ||
            'All security telemetry, alerts, and endpoints are simulated for cybersecurity operations training. Containment decisions record simulated mock responses to audit logs and will never affect real-world production networks or infrastructure.'}
        </p>
      </div>
    </div>
  );
}
