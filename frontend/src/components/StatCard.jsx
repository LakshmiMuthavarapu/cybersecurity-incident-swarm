import React from 'react';

export default function StatCard({ title, value, icon: Icon, color = 'blue', subtitle, onClick }) {
  const colorMap = {
    blue: { bg: '#e0f2fe', color: '#0284c7' },
    red: { bg: '#fee2e2', color: '#dc2626' },
    orange: { bg: '#ffedd5', color: '#ea580c' },
    amber: { bg: '#fef3c7', color: '#d97706' },
    green: { bg: '#dcfce7', color: '#16a34a' },
    purple: { bg: '#f3e8ff', color: '#9333ea' },
  };

  const scheme = colorMap[color] || colorMap.blue;

  return (
    <div
      className="stat-card"
      onClick={onClick}
      style={{ cursor: onClick ? 'pointer' : 'default' }}
    >
      <div className="stat-header">
        <span className="stat-title">{title}</span>
        <div
          className="stat-icon"
          style={{ backgroundColor: scheme.bg, color: scheme.color }}
        >
          {Icon && <Icon size={20} />}
        </div>
      </div>
      <div className="stat-value">{value}</div>
      {subtitle && <div className="stat-footer">{subtitle}</div>}
    </div>
  );
}
