function DonutChartCard({ title, items }) {
  const total = items.reduce((sum, item) => sum + item.value, 0) || 1
  let current = 0

  const segments = items.map((item) => {
    const start = (current / total) * 360
    current += item.value
    const end = (current / total) * 360
    return `${item.color} ${start}deg ${end}deg`
  })

  return (
    <div className="card chart-card large-card">
      <div className="card-title">{title}</div>

      <div className="donut-wrap">
        <div
          className="donut-chart"
          style={{
            background: `conic-gradient(${segments.join(', ')})`,
          }}
        >
          <div className="donut-inner" />
        </div>

        <div className="donut-legend">
          {items.map((item) => (
            <div className="legend-item" key={item.label}>
              <span
                className="legend-color"
                style={{ backgroundColor: item.color }}
              />
              <span>{item.label}</span>
              <strong>{item.value}</strong>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default DonutChartCard
