
import {
  Area,
  AreaChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

const COLORS = ['#ff7f0e', '#2ca02c', '#1f77b4', '#d62728', '#9467bd', '#8c564b']

function formatBytesPerSecond(value) {
  const num = Number(value)
  if (Number.isNaN(num) || num <= 0) return '0 B/s'
  if (num < 1024) return `${num.toFixed(0)} B/s`
  if (num < 1024 ** 2) return `${(num / 1024).toFixed(2)} KB/s`
  if (num < 1024 ** 3) return `${(num / 1024 ** 2).toFixed(2)} MB/s`
  if (num < 1024 ** 4) return `${(num / 1024 ** 3).toFixed(2)} GB/s`
  return `${(num / 1024 ** 4).toFixed(2)} TB/s`
}

function buildInterfaceKeys(history, prefix) {
  const keys = new Set()
  history.forEach((row) => {
    Object.keys(row || {}).forEach((key) => {
      if (key.startsWith(prefix)) keys.add(key)
    })
  })
  return Array.from(keys)
}

function CustomTrafficTooltip({ active, payload, label }) {
  if (!active || !payload || !payload.length) return null
  return (
    <div className="chart-tooltip">
      <div className="chart-tooltip__title">{label}</div>
      <div className="chart-tooltip__body">
        {payload.map((entry, idx) => (
          <div key={`${entry.dataKey}-${idx}`}>
            {entry.name}: {formatBytesPerSecond(entry.value)}
          </div>
        ))}
      </div>
    </div>
  )
}

function keyToLabel(key, prefix) {
  return key.replace(prefix, '')
}

function TrafficAreaChartCard({ title, history = [], error = '' }) {
  const rxKeys = buildInterfaceKeys(history, 'rx_')
  const txKeys = buildInterfaceKeys(history, 'tx_')

  return (
    <div className="card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>

      {error ? (
        <p className="error-text">{error}</p>
      ) : history.length < 2 ? (
        <p>실시간 속도 그래프를 그리기 위한 데이터가 아직 충분하지 않습니다.</p>
      ) : (
        <div className="traffic-stack">
          <div className="traffic-section">
            <h4 className="traffic-subtitle">수신트래픽</h4>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={history}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis tickFormatter={formatBytesPerSecond} width={90} domain={[0, 'dataMax + 10']} />
                <Tooltip content={<CustomTrafficTooltip />} />
                <Legend />
                {rxKeys.map((key, index) => (
                  <Area
                    key={key}
                    type="monotone"
                    dataKey={key}
                    name={keyToLabel(key, 'rx_')}
                    stroke={COLORS[index % COLORS.length]}
                    fill={COLORS[index % COLORS.length]}
                    fillOpacity={0.35}
                    strokeWidth={3}
                    connectNulls
                    isAnimationActive={false}
                    dot={false}
                    activeDot={{ r: 5 }}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="traffic-section">
            <h4 className="traffic-subtitle">발신트래픽</h4>
            <ResponsiveContainer width="100%" height={260}>
              <AreaChart data={history}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis tickFormatter={formatBytesPerSecond} width={90} domain={[0, 'dataMax + 10']} />
                <Tooltip content={<CustomTrafficTooltip />} />
                <Legend />
                {txKeys.map((key, index) => (
                  <Area
                    key={key}
                    type="monotone"
                    dataKey={key}
                    name={keyToLabel(key, 'tx_')}
                    stroke={COLORS[index % COLORS.length]}
                    fill={COLORS[index % COLORS.length]}
                    fillOpacity={0.35}
                    strokeWidth={3}
                    connectNulls
                    isAnimationActive={false}
                    dot={false}
                    activeDot={{ r: 5 }}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
    </div>
  )
}

export default TrafficAreaChartCard
