function SystemInfoCard({ title, items = [], error = '' }) {
  return (
    <div className="card">
      <div className="card-header-row"><h3>{title}</h3></div>
      {error ? (
        <p className="error-text">{String(error)}</p>
      ) : (
        <div className="summary-list">
          {items.map((item, idx) => (
            <div className="summary-row" key={`${item.label}-${idx}`}>
              <span className="summary-label">{item.label}</span>
              <span className="summary-value">{item.value}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default SystemInfoCard
