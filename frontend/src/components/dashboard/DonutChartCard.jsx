import { useState } from 'react'
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Sector,
  Tooltip,
} from 'recharts'

function formatBytes(value) {
  const num = Number(value)
  if (Number.isNaN(num) || num <= 0) return '0 B'
  if (num < 1024) return `${num.toFixed(0)} B`
  if (num < 1024 ** 2) return `${(num / 1024).toFixed(2)} KB`
  if (num < 1024 ** 3) return `${(num / 1024 ** 2).toFixed(2)} MB`
  if (num < 1024 ** 4) return `${(num / 1024 ** 3).toFixed(2)} GB`
  return `${(num / 1024 ** 4).toFixed(2)} TB`
}

function formatValue(value, type) {
  if (type === 'bytes') return formatBytes(value)
  if (type === 'percent') return `${Number(value || 0).toFixed(1)}%`
  return String(value)
}

function getTooltipRows(tooltipData = [], activeName) {
  if (activeName === 'used') {
    return tooltipData.filter((item) => item.label === '사용')
  }

  if (activeName === 'free') {
    return tooltipData.filter(
      (item) => item.label === '여유' || item.label === '가용',
    )
  }

  return []
}

function getTooltipTitle(activeName) {
  if (activeName === 'used') return '사용'
  if (activeName === 'free') return '여유'
  return ''
}

function CustomTooltip({ active, payload, tooltipData = [] }) {
  if (!active || !payload || !payload.length) return null

  const activeName = payload[0]?.name
  const rows = getTooltipRows(tooltipData, activeName)
  const title = getTooltipTitle(activeName)

  if (!rows.length) return null

  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip__title">{title}</div>
      <div className="chart-tooltip__body">
        {rows.map((item, index) => (
          <div key={`${item.label}-${index}`}>
            {item.label}: {formatValue(item.value, item.type)}
          </div>
        ))}
      </div>
    </div>
  )
}

function renderActiveSemiShape(props) {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill } = props

  return (
    <Sector
      cx={cx}
      cy={cy}
      innerRadius={innerRadius}
      outerRadius={outerRadius + 8}
      startAngle={startAngle}
      endAngle={endAngle}
      fill={fill}
      stroke="none"
    />
  )
}

function DonutChartCard({
  title,
  percent = 0,
  used = 0,
  total = 0,
  tooltipData = [],
  error = '',
}) {
  const [activeIndex, setActiveIndex] = useState(null)

  const safePercent = Math.max(0, Math.min(100, Number(percent) || 0))

  const chartData = [
    { name: 'used', value: safePercent, color: '#ef6c00' },
    { name: 'free', value: Math.max(100 - safePercent, 0), color: '#e0e0e0' },
  ]

  const usageText = `${formatBytes(used)} / ${formatBytes(total)}`

  return (
    <div className="card donut-card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>

      {error ? (
        <p className="error-text">{error}</p>
      ) : (
        <div className="semi-donut-wrap">
          <ResponsiveContainer width="100%" height={230}>
            <PieChart>
              <Pie
                data={chartData}
                dataKey="value"
                startAngle={180}
                endAngle={0}
                cx="50%"
                cy="88%"
                innerRadius="58%"
                outerRadius="88%"
                paddingAngle={1}
                activeIndex={activeIndex ?? undefined}
                activeShape={renderActiveSemiShape}
                onMouseEnter={(_, index) => setActiveIndex(index)}
                onMouseLeave={() => setActiveIndex(null)}
              >
                {chartData.map((entry, index) => {
                  const isActive = activeIndex === null || activeIndex === index

                  return (
                    <Cell
                      key={`${entry.name}-${index}`}
                      fill={entry.color}
                      fillOpacity={isActive ? 1 : 0.22}
                      stroke="none"
                    />
                  )
                })}
              </Pie>
              <Tooltip content={<CustomTooltip tooltipData={tooltipData} />} />
            </PieChart>
          </ResponsiveContainer>

          <div className="semi-donut-center">
            <div className="semi-donut-percent">{safePercent.toFixed(1)}%</div>
            <div className="semi-donut-usage">{usageText}</div>
          </div>
        </div>
      )}
    </div>
  )
}

export default DonutChartCard
