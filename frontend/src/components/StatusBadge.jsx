import React from 'react';
import { Clock, ShieldCheck, CheckCircle2, AlertOctagon, HelpCircle } from 'lucide-react';

export default function StatusBadge({ status }) {
  const st = (status || 'NEW').toUpperCase();

  switch (st) {
    case 'OPEN':
    case 'NEW':
      return (
        <span className="badge badge-open">
          <AlertOctagon size={11} />
          {st}
        </span>
      );
    case 'INVESTIGATING':
      return (
        <span className="badge badge-investigating">
          <Clock size={11} />
          INVESTIGATING
        </span>
      );
    case 'AWAITING_REVIEW':
      return (
        <span className="badge badge-awaiting">
          <HelpCircle size={11} />
          AWAITING REVIEW
        </span>
      );
    case 'CONTAINED':
      return (
        <span className="badge badge-contained">
          <ShieldCheck size={11} />
          CONTAINED
        </span>
      );
    case 'RESOLVED':
    case 'VERIFIED':
      return (
        <span className="badge badge-resolved">
          <CheckCircle2 size={11} />
          {st}
        </span>
      );
    case 'PENDING':
    case 'PENDING_REVIEW':
      return (
        <span className="badge badge-pending">
          <Clock size={11} />
          {st.replace('_', ' ')}
        </span>
      );
    case 'REJECTED':
      return (
        <span className="badge badge-open">
          <AlertOctagon size={11} />
          REJECTED
        </span>
      );
    case 'APPROVED':
    case 'SIMULATED_EXECUTED':
      return (
        <span className="badge badge-contained">
          <ShieldCheck size={11} />
          {st === 'SIMULATED_EXECUTED' ? 'SIM EXECUTED' : 'APPROVED'}
        </span>
      );
    default:
      return <span className="badge badge-info">{st}</span>;
  }
}
