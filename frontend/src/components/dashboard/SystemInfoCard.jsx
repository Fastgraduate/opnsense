
function SystemInfoCard({ title, items = [], error = '' }) {
  return (
    <div className="card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>
      {error ? (
        <p className="error-text">{error}</p>
      ) : (
        <div className="summary-list">
          {items.map((item) => (
            <div key={item.label} className="summary-row">
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
