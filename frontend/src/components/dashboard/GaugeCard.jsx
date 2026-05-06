function GaugeCard({ title, value, color = 'default' }) {
  return (
    <div className="card gauge-card">
      <div className="card-title">{title}</div>
      <div className={`gauge-circle ${color === 'orange' ? 'orange' : ''}`}>
        <div className="gauge-value">{value}%</div>
      </div>
      <p className="muted-text">대시보드 표시용</p>
    </div>
  )
}

export default GaugeCard
