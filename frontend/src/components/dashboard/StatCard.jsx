function StatCard({ title, value, subValue = '' }) {
  return (
    <div className="card stat-card">
      <div className="stat-card__title">{title}</div>
      <div className="stat-card__value">{value}</div>
      <div className="stat-card__sub">{subValue}</div>
    </div>
  )
}

export default StatCard
