import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Chart,
  ArcElement,
  Tooltip,
  Legend,
} from 'chart.js'

Chart.register(ArcElement, Tooltip, Legend)

const DEFAULT_FILTERS = {
  historySize: 5000,
  autoRefresh: true,
}

const REFRESH_INTERVAL_MS = 15000
const TOP_LIMIT = 10

const CATEGORY_OPTIONS = [
  { key: 'action', label: '작업', tableLabel: '작업' },
  { key: 'interface', label: '인터페이스', tableLabel: '인터페이스' },
  { key: 'protocol', label: '프로토콜', tableLabel: '프로토콜' },
  { key: 'sourceIp', label: '출발지 IP', tableLabel: '출발지 IP' },
  { key: 'destinationIp', label: '목적지 IP', tableLabel: '목적지 IP' },
  { key: 'sourcePort', label: '출발지 포트', tableLabel: '출발지 포트' },
  { key: 'destinationPort', label: '목적지 포트', tableLabel: '목적지 포트' },
]

const CHART_COLORS = [
  '#3b82f6',
  '#93c5fd',
  '#f97316',
  '#fdba74',
  '#22c55e',
  '#86efac',
  '#ef4444',
  '#fca5a5',
  '#8b5cf6',
  '#c4b5fd',
  '#a16207',
]

const toDisplayText = (value, fallback = '-') => {
  if (value == null || value === '') return fallback

  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value)
  }

  if (Array.isArray(value)) {
    const text = value
      .map((item) => toDisplayText(item, ''))
      .filter(Boolean)
      .join(', ')

    return text || fallback
  }

  if (typeof value === 'object') {
    if (value.name) return String(value.name)
    if (value.hostname) return String(value.hostname)
    if (value.ip) return toDisplayText(value.ip, fallback)
    if (value.address) return String(value.address)
    if (value.value) return toDisplayText(value.value, fallback)

    return JSON.stringify(value)
  }

  return fallback
}

const splitAddress = (value) => {
  const text = toDisplayText(value, '')

  if (!text || text === '-') {
    return {
      ip: '-',
      port: '-',
    }
  }

  // IPv6 주소가 포함될 수 있으므로 마지막 콜론 뒤 숫자만 포트로 본다.
  const match = text.match(/^(.*):(\d+)$/)

  if (!match) {
    return {
      ip: text,
      port: '-',
    }
  }

  return {
    ip: match[1],
    port: match[2],
  }
}

const normalizeAddress = (ip, port) => {
  const safeIp = toDisplayText(ip, '')
  const safePort = toDisplayText(port, '')

  if (!safeIp && !safePort) return '-'
  if (safeIp && safePort && safePort !== '-') return `${safeIp}:${safePort}`

  return safeIp || safePort || '-'
}

const normalizeOneLog = (item, index) => {
  const src = item?._source || item?.raw || item || {}

  const interfaceName =
    item.interface ||
    item.if ||
    item.iface ||
    src.interface ||
    src.if ||
    src.iface ||
    '-'

  const direction = item.direction || item.dir || src.direction || src.dir || '-'

  const time =
    item.time ||
    item.timestamp ||
    item.datetime ||
    item.__timestamp__ ||
    src.time ||
    src.timestamp ||
    src.datetime ||
    src.__timestamp__ ||
    '-'

  const protocol =
    item.protocol ||
    item.proto ||
    item.protoname ||
    src.protocol ||
    src.proto ||
    src.protoname ||
    '-'

  const sourceIp =
    item.source_ip ||
    item.src_ip ||
    item.src ||
    item.source ||
    src.source_ip ||
    src.src_ip ||
    src.src ||
    src.source ||
    '-'

  const sourcePort =
    item.source_port ||
    item.src_port ||
    item.srcport ||
    src.source_port ||
    src.src_port ||
    src.srcport ||
    ''

  const destinationIp =
    item.destination_ip ||
    item.dest_ip ||
    item.dst_ip ||
    item.destination ||
    item.dest ||
    item.dst ||
    src.destination_ip ||
    src.dest_ip ||
    src.dst_ip ||
    src.destination ||
    src.dest ||
    src.dst ||
    '-'

  const destinationPort =
    item.destination_port ||
    item.dest_port ||
    item.dst_port ||
    item.dstport ||
    src.destination_port ||
    src.dest_port ||
    src.dst_port ||
    src.dstport ||
    ''

  const source = normalizeAddress(sourceIp, sourcePort)
  const destination = normalizeAddress(destinationIp, destinationPort)
  const parsedSource = splitAddress(source)
  const parsedDestination = splitAddress(destination)

  const action =
    item.action ||
    item.act ||
    src.action ||
    src.act ||
    '-'

  const label =
    item.label ||
    item.rule ||
    item.descr ||
    item.description ||
    src.label ||
    src.rule ||
    src.descr ||
    src.description ||
    '-'

  return {
    id:
      item.id ||
      item.uuid ||
      item.__digest__ ||
      src.id ||
      src.uuid ||
      src.__digest__ ||
      `${time}-${index}`,
    interface: toDisplayText(interfaceName).toLowerCase(),
    direction: toDisplayText(direction),
    time: toDisplayText(time),
    protocol: toDisplayText(protocol).toLowerCase(),
    source,
    destination,
    sourceIp: parsedSource.ip,
    sourcePort: parsedSource.port,
    destinationIp: parsedDestination.ip,
    destinationPort: parsedDestination.port,
    action: toDisplayText(action).toLowerCase(),
    label: toDisplayText(label),
    raw: src,
  }
}

const normalizeLogs = (payload) => {
  let list = []

  if (Array.isArray(payload?.rows)) list = payload.rows
  else if (Array.isArray(payload?.data?.rows)) list = payload.data.rows
  else if (Array.isArray(payload?.logs)) list = payload.logs
  else if (Array.isArray(payload?.data)) list = payload.data
  else if (Array.isArray(payload)) list = payload

  return list.map((item, index) => normalizeOneLog(item, index))
}

const formatTime = (value) => {
  if (!value || value === '-') return '-'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString('ko-KR', { hour12: false })
}

const getLogValueByCategory = (log, categoryKey) => {
  if (categoryKey === 'action') return log.action
  if (categoryKey === 'interface') {
    if (log.interface === 'em0') return 'wan'
    if (log.interface === 'em1') return 'lan'
    return log.interface
  }
  if (categoryKey === 'protocol') return log.protocol
  if (categoryKey === 'sourceIp') return log.sourceIp
  if (categoryKey === 'destinationIp') return log.destinationIp
  if (categoryKey === 'sourcePort') return log.sourcePort
  if (categoryKey === 'destinationPort') return log.destinationPort

  return '-'
}

const buildCategoryRows = (logs, categoryKey) => {
  const map = new Map()

  logs.forEach((log) => {
    const rawValue = getLogValueByCategory(log, categoryKey)
    const key = toDisplayText(rawValue)

    if (!key || key === '-') return

    map.set(key, (map.get(key) || 0) + 1)
  })

  const sorted = Array.from(map.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)

  if (sorted.length <= TOP_LIMIT) return sorted

  const top = sorted.slice(0, TOP_LIMIT)
  const otherCount = sorted
    .slice(TOP_LIMIT)
    .reduce((sum, item) => sum + item.count, 0)

  if (otherCount > 0) {
    top.push({
      label: '기타',
      count: otherCount,
    })
  }

  return top
}

function DonutChart({ rows, total }) {
  const canvasRef = useRef(null)
  const chartRef = useRef(null)

  const labels = useMemo(() => rows.map((row) => row.label), [rows])
  const values = useMemo(() => rows.map((row) => row.count), [rows])
  const colors = useMemo(
    () => rows.map((_, index) => CHART_COLORS[index % CHART_COLORS.length]),
    [rows],
  )

  useEffect(() => {
    if (!canvasRef.current || chartRef.current) return

    chartRef.current = new Chart(canvasRef.current, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [
          {
            data: values,
            backgroundColor: colors,
            borderColor: '#ffffff',
            borderWidth: 2,
            hoverOffset: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '46%',
        animation: {
          duration: 650,
          easing: 'easeOutQuart',
        },
        plugins: {
          legend: {
            position: 'right',
            labels: {
              usePointStyle: true,
              boxWidth: 9,
              boxHeight: 9,
              color: '#0f172a',
              font: {
                size: 12,
                weight: '700',
              },
            },
          },
          tooltip: {
            backgroundColor: '#111827',
            titleColor: '#ffffff',
            bodyColor: '#e5e7eb',
            padding: 10,
            callbacks: {
              label: (context) => {
                const value = Number(context.raw || 0)
                const percent = total > 0 ? Math.round((value / total) * 100) : 0
                return `${context.label}: ${value.toLocaleString()}건 (${percent}%)`
              },
            },
          },
        },
      },
      plugins: [
        {
          id: 'percentageLabel',
          afterDatasetsDraw(chart) {
            const { ctx } = chart
            const dataset = chart.data.datasets[0]
            const meta = chart.getDatasetMeta(0)

            ctx.save()
            ctx.fillStyle = '#0f172a'
            ctx.font = '700 12px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
            ctx.textAlign = 'center'
            ctx.textBaseline = 'middle'

            meta.data.forEach((arc, index) => {
              const value = Number(dataset.data[index] || 0)
              if (!value || !total) return

              const percent = Math.round((value / total) * 100)

              // 작은 조각은 글자가 겹치므로 5% 이상만 표시
              if (percent < 5) return

              const position = arc.tooltipPosition()
              ctx.fillText(`${percent}%`, position.x, position.y)
            })

            ctx.restore()
          },
        },
      ],
    })

    return () => {
      if (chartRef.current) {
        chartRef.current.destroy()
        chartRef.current = null
      }
    }
  }, [])

  useEffect(() => {
    if (!chartRef.current) return

    const chart = chartRef.current
    chart.data.labels = labels
    chart.data.datasets[0].data = values
    chart.data.datasets[0].backgroundColor = colors
    chart.update()
  }, [labels, values, colors])

  return (
    <div className="opn-overview-chart">
      <canvas ref={canvasRef} />
    </div>
  )
}

function OpnsenseLogOverviewPage({ selectedFirewall, fetchOpnsenseLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [activeCategory, setActiveCategory] = useState('action')
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)
  const [error, setError] = useState('')

  const timerRef = useRef(null)
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'
  const activeMeta =
    CATEGORY_OPTIONS.find((item) => item.key === activeCategory) ||
    CATEGORY_OPTIONS[0]

  const loadLogs = async ({ silent = false } = {}) => {
    if (loadingRef.current) return

    if (!selectedFirewall) {
      setLogs([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    try {
      loadingRef.current = true

      if (!silent) setLoading(true)

      setError('')

      const data = await fetchOpnsenseLogs({
        search: '',
        field: 'any',
        operator: 'contains',
        tableSize: filters.historySize,
        historySize: filters.historySize,
        resolveHostnames: false,
        onlyImportant: false,
      })

      setLogs(normalizeLogs(data))
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err.message || 'OPNsense 로그 개요를 불러오지 못했습니다.')
    } finally {
      loadingRef.current = false

      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [selectedFirewall])

  useEffect(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }

    if (!filters.autoRefresh || !selectedFirewall) return

    timerRef.current = setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadLogs({ silent: true })
      }
    }, REFRESH_INTERVAL_MS)

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current)
        timerRef.current = null
      }
    }
  }, [filters.autoRefresh, filters.historySize, selectedFirewall])

  const categoryRows = useMemo(
    () => buildCategoryRows(logs, activeCategory),
    [logs, activeCategory],
  )

  const total = useMemo(
    () => categoryRows.reduce((sum, item) => sum + item.count, 0),
    [categoryRows],
  )

  const topItem = categoryRows[0] || null

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target

    setFilters((prev) => ({
      ...prev,
      [name]:
        type === 'checkbox'
          ? checked
          : name === 'historySize'
            ? Number(value)
            : value,
    }))
  }

  return (
    <div className="opn-overview-page">
      <section className="opn-overview-hero">
        <div>
          <p className="opn-log-eyebrow">OPNsense Log Summary</p>
          <h2>방화벽 로그 파일: 개요</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className={`opn-log-status ${loading ? 'loading' : 'ready'}`}>
          <i />
          {loading ? '개요 갱신 중' : '개요 수집 대기 중'}
        </div>
      </section>

      <section className="opn-overview-toolbar">
        <div className="opn-overview-tabs">
          {CATEGORY_OPTIONS.map((item) => (
            <button
              key={item.key}
              type="button"
              className={activeCategory === item.key ? 'active' : ''}
              onClick={() => setActiveCategory(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div className="opn-overview-controls">
          <label>
            <input
              type="checkbox"
              name="autoRefresh"
              checked={filters.autoRefresh}
              onChange={handleChange}
            />
            자동 갱신
          </label>

          <select
            name="historySize"
            value={filters.historySize}
            onChange={handleChange}
          >
            <option value={100}>100개</option>
            <option value={500}>500개</option>
            <option value={1000}>1000개</option>
            <option value={5000}>5000개</option>
            <option value={10000}>10000개</option>
          </select>

          <button type="button" onClick={() => loadLogs()}>
            갱신
          </button>
        </div>
      </section>

      {error ? <div className="opn-log-error">{error}</div> : null}

      <section className="opn-overview-card">
        <div className="opn-overview-card-header">
          <div>
            <p className="opn-log-eyebrow">Category</p>
            <h3>{activeMeta.label} 기준 로그 분포</h3>
            <span>
              전체 {logs.length.toLocaleString()}건 / 집계 {total.toLocaleString()}건
              {lastUpdatedAt
                ? ` / 마지막 갱신: ${lastUpdatedAt.toLocaleTimeString()}`
                : ''}
            </span>
          </div>

          {topItem ? (
            <div className="opn-overview-top">
              <span>최다 항목</span>
              <strong>{topItem.label}</strong>
              <em>{topItem.count.toLocaleString()}건</em>
            </div>
          ) : null}
        </div>

        {categoryRows.length === 0 ? (
          <div className="opn-overview-empty">
            표시할 로그 개요 데이터가 없습니다.
          </div>
        ) : (
          <>
            <DonutChart rows={categoryRows} total={total} />

            <div className="opn-overview-table-wrap">
              <table className="opn-overview-table">
                <thead>
                  <tr>
                    <th>{activeMeta.tableLabel}</th>
                    <th>#</th>
                  </tr>
                </thead>

                <tbody>
                  {categoryRows.map((row) => (
                    <tr key={row.label}>
                      <td>{row.label}</td>
                      <td>{row.count.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </section>
    </div>
  )
}

export default OpnsenseLogOverviewPage
