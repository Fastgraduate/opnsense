import { useState } from 'react'
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Sector,
  Tooltip,
} from 'recharts'

const COLORS = [
  '#ff7f0e',
  '#2ca02c',
  '#1f77b4',
  '#d62728',
  '#9467bd',
  '#8c564b',
]

function formatBytes(value) {
  const num = Number(value)
  if (Number.isNaN(num) || num <= 0) return '0 B'
  if (num < 1024) return `${num.toFixed(0)} B`
  if (num < 1024 ** 2) return `${(num / 1024).toFixed(2)} KB`
  if (num < 1024 ** 3) return `${(num / 1024 ** 2).toFixed(2)} MB`
  if (num < 1024 ** 4) return `${(num / 1024 ** 3).toFixed(2)} GB`
  return `${(num / 1024 ** 4).toFixed(2)} TB`
}

function formatNumber(value) {
  const num = Number(value)
  if (Number.isNaN(num)) return '0'
  return num.toLocaleString()
}

function CustomTooltip({ active, payload, type }) {
  if (!active || !payload || !payload.length) return null

  const item = payload[0].payload

  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip__title">{item.label}</div>

      {type === 'interface' ? (
        <div className="chart-tooltip__body">
          <div>수신 바이트: {formatBytes(item.meta?.rxBytes)}</div>
          <div>송신 바이트: {formatBytes(item.meta?.txBytes)}</div>
          <div>수신 패킷: {formatNumber(item.meta?.rxPackets)}</div>
          <div>송신 패킷: {formatNumber(item.meta?.txPackets)}</div>
          <div>수신 오류: {formatNumber(item.meta?.rxErrors)}</div>
          <div>송신 오류: {formatNumber(item.meta?.txErrors)}</div>
          <div>충돌: {formatNumber(item.meta?.collisions)}</div>
          <div>
            표시 기준: {item.meta?.unit === 'bytes' ? '바이트' : '패킷'}
          </div>
        </div>
      ) : (
        <div className="chart-tooltip__body">
          <div>규칙 수: {formatNumber(item.value)}</div>
        </div>
      )}
    </div>
  )
}

function renderActiveShape(props) {
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

function MultiDonutChartCard({
  title,
  segments = [],
  emptyText = '표시할 데이터가 없습니다.',
  type = 'default',
  centerLabel = '',
}) {
  const [activeIndex, setActiveIndex] = useState(null)
  const data = segments.filter((item) => Number(item.value) > 0)

  return (
    <div className="card donut-card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>

      {data.length === 0 ? (
        <p>{emptyText}</p>
      ) : (
        <div className="multi-donut-layout">
          <div className="multi-donut-chart-area">
            <div className="rechart-pie-wrap single-donut">
              <ResponsiveContainer width="100%" height={320}>
                <PieChart>
                  <Pie
                    data={data}
                    dataKey="value"
                    nameKey="label"
                    innerRadius={70}
                    outerRadius={140}
                    paddingAngle={2}
                    activeIndex={activeIndex ?? undefined}
                    activeShape={renderActiveShape}
                    onMouseEnter={(_, index) => setActiveIndex(index)}
                    onMouseLeave={() => setActiveIndex(null)}
                  >
                    {data.map((entry, index) => {
                      const isActive =
                        activeIndex === null || activeIndex === index
                      return (
                        <Cell
                          key={`${entry.label}-${index}`}
                          fill={COLORS[index % COLORS.length]}
                          fillOpacity={isActive ? 1 : 0.22}
                          stroke="none"
                        />
                      )
                    })}
                  </Pie>
                  <Tooltip content={<CustomTooltip type={type} />} />
                </PieChart>
              </ResponsiveContainer>

              {centerLabel ? (
                <div className="donut-center-label">{centerLabel}</div>
              ) : null}
            </div>
          </div>

          <div className="outside-legend">
            {data.map((item, index) => {
              const isActive = activeIndex === null || activeIndex === index
              return (
                <div
                  key={`${item.label}-${index}`}
                  className="outside-legend__item"
                  style={{ opacity: isActive ? 1 : 0.35 }}
                >
                  <span
                    className="outside-legend__dot"
                    style={{ backgroundColor: COLORS[index % COLORS.length] }}
                  />
                  <span className="outside-legend__label">{item.label}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

export default MultiDonutChartCard
