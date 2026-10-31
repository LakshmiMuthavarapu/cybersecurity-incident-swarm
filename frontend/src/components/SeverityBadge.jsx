import React from 'react';
import { AlertCircle, AlertTriangle, Info, ShieldAlert } from 'lucide-react';

export default function SeverityBadge({ severity }) {
  const sev = (severity || 'INFO').toUpperCase();

  switch (sev) {
    case 'CRITICAL':
      return (
        <span className="badge badge-critical">
          <ShieldAlert size={12} />
          CRITICAL
        </span>
      );
    case 'HIGH':
      return (
        <span className="badge badge-high">
          <AlertCircle size={12} />
          HIGH
        </span>
      );
    case 'MEDIUM':
      return (
        <span className="badge badge-medium">
          <AlertTriangle size={12} />
          MEDIUM
        </span>
      );
    case 'LOW':
      return (
        <span className="badge badge-low">
          <Info size={12} />
          LOW
        </span>
      );
    default:
      return (
        <span className="badge badge-info">
          <Info size={12} />
          {sev}
        </span>
      );
  }
}
