function SystemInfoCard({ title, items = [], error = '' }) {
  return (
    <div className="card summary-card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>

      {error && <div className="error-text">{error}</div>}

      <div className="summary-list">
        {items.map((item, idx) => (
          <div key={`${item.label}-${idx}`} className="summary-row">
            <span className="summary-label">{item.label}</span>
            <span className="summary-value">{item.value}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

export default SystemInfoCard
