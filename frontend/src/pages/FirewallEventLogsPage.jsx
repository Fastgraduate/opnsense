import { useEffect, useMemo, useRef, useState } from 'react'
import '../styles/logCsvExport.css'
import {
  KIBANA_EXPORT_COLUMNS,
  buildElasticExportRows,
  downloadCsv,
  makeTimestampedFilename,
} from '../utils/logCsvExport'

const DEFAULT_FILTERS = {
  minutes: 60,
  size: 200,
  action: '',
  interface: '',
  query: '',
  eventType: '',
  protocol: '',
  sourceIp: '',
  destinationIp: '',
  severity: '',
}

const PRESETS = [
  {
    key: 'recent',
    label: '최근 로그',
    description: '최근 1시간 전체 로그',
    filters: {
      minutes: 60,
      size: 200,
      action: '',
      interface: '',
      query: '',
      eventType: '',
      protocol: '',
      sourceIp: '',
      destinationIp: '',
      severity: '',
    },
  },
  {
    key: 'alert',
    label: 'Alert',
    description: 'Suricata alert 이벤트',
    filters: {
      minutes: 360,
      size: 200,
      action: 'alert',
      eventType: 'alert',
      query: '',
    },
  },
  {
    key: 'flow',
    label: 'Flow',
    description: 'Flow 이벤트',
    filters: {
      minutes: 60,
      size: 200,
      action: 'flow',
      eventType: 'flow',
      query: '',
    },
  },
  {
    key: 'dns',
    label: 'DNS',
    description: 'DNS 관련 로그',
    filters: {
      minutes: 360,
      size: 200,
      action: '',
      eventType: 'dns',
      query: 'dns',
      protocol: '',
    },
  },
  {
    key: 'http',
    label: 'HTTP',
    description: 'HTTP 관련 로그',
    filters: {
      minutes: 360,
      size: 200,
      action: '',
      eventType: 'http',
      query: 'http',
      protocol: '',
    },
  },
  {
    key: 'tcp',
    label: 'TCP',
    description: 'TCP 트래픽',
    filters: {
      minutes: 60,
      size: 200,
      action: '',
      eventType: '',
      query: 'TCP',
      protocol: 'tcp',
    },
  },
  {
    key: 'udp',
    label: 'UDP',
    description: 'UDP 트래픽',
    filters: {
      minutes: 60,
      size: 200,
      action: '',
      eventType: '',
      query: 'UDP',
      protocol: 'udp',
    },
  },
  {
    key: 'important',
    label: '중요 로그',
    description: 'alert/drop/block/deny 중심',
    filters: {
      minutes: 1440,
      size: 300,
      action: '',
      eventType: '',
      query: 'alert drop block deny',
    },
  },
]

const CHART_OPTIONS = [
  { key: 'event_type', label: '이벤트 타입' },
  { key: 'interface', label: '인터페이스' },
  { key: 'protocol', label: '프로토콜' },
  { key: 'severity', label: '심각도' },
  { key: 'category', label: '카테고리' },
  { key: 'source_ip', label: '출발지 IP' },
  { key: 'destination_ip', label: '목적지 IP' },
]

const toText = (value, fallback = '-') => {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

const lower = (value) => String(value ?? '').toLowerCase()

const includesText = (source, needle) => {
  if (!needle) return true
  return lower(source).includes(lower(needle))
}

const normalizeEventType = (row) => {
  return (
    row.event_type ||
    row.action ||
    row?.messageJson?.event_type ||
    row?.raw?.event_type ||
    '-'
  )
}

const normalizeProtocol = (row) => {
  return (
    row.protocol ||
    row?.messageJson?.proto ||
    row?.raw?.proto ||
    row?.raw?.network?.transport ||
    '-'
  )
}

const getRowValue = (row, key) => {
  if (key === 'event_type') return normalizeEventType(row)
  if (key === 'protocol') return normalizeProtocol(row)

  return row?.[key] ?? row?.messageJson?.[key] ?? row?.raw?.[key] ?? '-'
}

const buildChartRows = (rows, key) => {
  const map = new Map()

  rows.forEach((row) => {
    const value = toText(getRowValue(row, key), '')
    if (!value || value === '-') return

    map.set(value, (map.get(value) || 0) + 1)
  })

  const sorted = Array.from(map.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)

  const top = sorted.slice(0, 10)
  const otherCount = sorted.slice(10).reduce((sum, item) => sum + item.count, 0)

  if (otherCount > 0) {
    top.push({ label: '기타', count: otherCount })
  }

  return top
}

function BarChart({ rows }) {
  const max = Math.max(...rows.map((row) => row.count), 1)

  if (!rows.length) {
    return (
      <div className="event-log-chart-empty">
        차트로 표시할 데이터가 없습니다.
      </div>
    )
  }

  return (
    <div className="event-log-bar-chart">
      {rows.map((row, index) => {
        const percent = Math.max((row.count / max) * 100, 3)

        return (
          <div key={`${row.label}-${index}`} className="event-log-bar-row">
            <div className="event-log-bar-label" title={row.label}>
              {row.label}
            </div>

            <div className="event-log-bar-track">
              <div
                className="event-log-bar-fill"
                style={{ width: `${percent}%` }}
              />
            </div>

            <div className="event-log-bar-count">
              {row.count.toLocaleString()}건
            </div>
          </div>
        )
      })}
    </div>
  )
}

function EventDetailModal({ log, onClose }) {
  if (!log) return null

  return (
    <div className="event-log-modal-backdrop" onClick={onClose}>
      <div className="event-log-modal" onClick={(e) => e.stopPropagation()}>
        <div className="event-log-modal-header">
          <div>
            <p className="event-log-eyebrow">Event Detail</p>
            <h3>이벤트 로그 상세</h3>
          </div>

          <button type="button" onClick={onClose}>
            닫기
          </button>
        </div>

        <div className="event-log-modal-summary">
          <span>시간: {toText(log.timestamp)}</span>
          <span>이벤트: {toText(normalizeEventType(log))}</span>
          <span>인터페이스: {toText(log.interface)}</span>
          <span>출발지: {toText(log.source_ip)}:{toText(log.source_port, '')}</span>
          <span>
            목적지: {toText(log.destination_ip)}:{toText(log.destination_port, '')}
          </span>
        </div>

        <pre className="event-log-modal-pre">
          {JSON.stringify(log.raw || log, null, 2)}
        </pre>
      </div>
    </div>
  )
}

function FirewallEventLogsPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [logs, setLogs] = useState([])
  const [exportColumns, setExportColumns] = useState(KIBANA_EXPORT_COLUMNS)
  const [chartKey, setChartKey] = useState('event_type')
  const [activePreset, setActivePreset] = useState('recent')
  const [selectedLog, setSelectedLog] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'

  const clientFilteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const eventType = normalizeEventType(log)
      const protocol = normalizeProtocol(log)

      if (filters.eventType && !includesText(eventType, filters.eventType)) {
        return false
      }

      if (filters.protocol && !includesText(protocol, filters.protocol)) {
        return false
      }

      if (filters.sourceIp && !includesText(log.source_ip, filters.sourceIp)) {
        return false
      }

      if (
        filters.destinationIp &&
        !includesText(log.destination_ip, filters.destinationIp)
      ) {
        return false
      }

      if (filters.severity && !includesText(log.severity, filters.severity)) {
        return false
      }

      return true
    })
  }, [
    logs,
    filters.eventType,
    filters.protocol,
    filters.sourceIp,
    filters.destinationIp,
    filters.severity,
  ])

  const displayRows = useMemo(() => {
    return clientFilteredLogs.slice(0, Math.min(Number(filters.size) || 200, 300))
  }, [clientFilteredLogs, filters.size])

  const chartRows = useMemo(
    () => buildChartRows(clientFilteredLogs, chartKey),
    [clientFilteredLogs, chartKey],
  )

  const stats = useMemo(() => {
    const total = clientFilteredLogs.length
    const alert = clientFilteredLogs.filter(
      (row) => lower(normalizeEventType(row)) === 'alert',
    ).length
    const flow = clientFilteredLogs.filter(
      (row) => lower(normalizeEventType(row)) === 'flow',
    ).length
    const uniqueSources = new Set(
      clientFilteredLogs
        .map((row) => row.source_ip)
        .filter((value) => value && value !== '-'),
    ).size

    return { total, alert, flow, uniqueSources }
  }, [clientFilteredLogs])

  const handleChange = (e) => {
    const { name, value } = e.target

    setActivePreset('custom')
    setFilters((prev) => ({ ...prev, [name]: value }))
  }

  const applyPreset = (preset) => {
    setActivePreset(preset.key)
    setFilters((prev) => ({
      ...prev,
      ...preset.filters,
    }))
  }

  const resetFilters = () => {
    setActivePreset('recent')
    setFilters(DEFAULT_FILTERS)
  }

  const loadLogs = async () => {
    if (!selectedFirewall || loadingRef.current) return

    try {
      loadingRef.current = true
      setLoading(true)
      setError('')

      const data = await fetchEventLogs({
        size: Math.min(Number(filters.size) || 200, 300),
        minutes: Number(filters.minutes) || 60,
        action: filters.action,
        interface: filters.interface,
        query: filters.query,
      })

      setLogs(Array.isArray(data?.rows) ? data.rows : [])
      setExportColumns(
        Array.isArray(data?.exportColumns) && data.exportColumns.length > 0
          ? data.exportColumns
          : KIBANA_EXPORT_COLUMNS,
      )
    } catch (err) {
      setLogs([])
      setError(err.message || '이벤트 로그 조회 실패')
    } finally {
      loadingRef.current = false
      setLoading(false)
    }
  }

  const handleExportCsv = () => {
    downloadCsv(
      makeTimestampedFilename('kibana_discover_logs'),
      exportColumns,
      buildElasticExportRows(clientFilteredLogs),
    )
  }

  useEffect(() => {
    loadLogs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall])

  return (
    <div className="event-log-page">
      <section className="event-log-header event-log-card">
        <div>
          <p className="event-log-eyebrow">Elastic / Kibana Logs</p>
          <h2>방화벽 이벤트 로그</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className="event-log-actions">
          <button type="button" onClick={loadLogs} disabled={loading}>
            {loading ? '조회 중...' : '조회'}
          </button>

          <button
            type="button"
            className="csv"
            onClick={handleExportCsv}
            disabled={clientFilteredLogs.length === 0}
          >
            CSV 내보내기
          </button>
        </div>
      </section>

      {error ? <div className="event-log-error">에러: {error}</div> : null}

      <section className="event-log-preset-card event-log-card">
        <div className="event-log-section-title">
          <div>
            <p>Presets</p>
            <h3>프리셋</h3>
          </div>

          <button type="button" onClick={resetFilters}>
            초기화
          </button>
        </div>

        <div className="event-log-preset-grid">
          {PRESETS.map((preset) => (
            <button
              key={preset.key}
              type="button"
              className={activePreset === preset.key ? 'active' : ''}
              onClick={() => applyPreset(preset)}
            >
              <strong>{preset.label}</strong>
              <span>{preset.description}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="event-log-filter-card event-log-card">
        <div className="event-log-section-title">
          <div>
            <p>Filters</p>
            <h3>필터</h3>
          </div>
        </div>

        <div className="event-log-filter-grid expanded">
          <label>
            조회 범위
            <select name="minutes" value={filters.minutes} onChange={handleChange}>
              <option value="15">최근 15분</option>
              <option value="60">최근 1시간</option>
              <option value="360">최근 6시간</option>
              <option value="1440">최근 24시간</option>
            </select>
          </label>

          <label>
            조회 개수
            <select name="size" value={filters.size} onChange={handleChange}>
              <option value="50">50개</option>
              <option value="100">100개</option>
              <option value="200">200개</option>
              <option value="300">300개</option>
            </select>
          </label>

          <label>
            서버 Action/Event
            <input
              name="action"
              value={filters.action}
              onChange={handleChange}
              placeholder="alert, flow..."
            />
          </label>

          <label>
            서버 Interface
            <input
              name="interface"
              value={filters.interface}
              onChange={handleChange}
              placeholder="ens33, em0..."
            />
          </label>

          <label>
            서버 검색어
            <input
              name="query"
              value={filters.query}
              onChange={handleChange}
              placeholder="IP, signature, message..."
              onKeyDown={(e) => {
                if (e.key === 'Enter') loadLogs()
              }}
            />
          </label>

          <label>
            이벤트 타입
            <input
              name="eventType"
              value={filters.eventType}
              onChange={handleChange}
              placeholder="alert, flow, dns..."
            />
          </label>

          <label>
            프로토콜
            <input
              name="protocol"
              value={filters.protocol}
              onChange={handleChange}
              placeholder="tcp, udp, icmp..."
            />
          </label>

          <label>
            출발지 IP
            <input
              name="sourceIp"
              value={filters.sourceIp}
              onChange={handleChange}
              placeholder="10.80..."
            />
          </label>

          <label>
            목적지 IP
            <input
              name="destinationIp"
              value={filters.destinationIp}
              onChange={handleChange}
              placeholder="8.8.8.8..."
            />
          </label>

          <label>
            심각도
            <input
              name="severity"
              value={filters.severity}
              onChange={handleChange}
              placeholder="1, 2, 3..."
            />
          </label>
        </div>
      </section>

      <section className="event-log-stats-grid">
        <article className="event-log-stat-card">
          <span>표시 로그</span>
          <strong>{stats.total.toLocaleString()}</strong>
        </article>

        <article className="event-log-stat-card">
          <span>Alert</span>
          <strong>{stats.alert.toLocaleString()}</strong>
        </article>

        <article className="event-log-stat-card">
          <span>Flow</span>
          <strong>{stats.flow.toLocaleString()}</strong>
        </article>

        <article className="event-log-stat-card">
          <span>출발지 IP</span>
          <strong>{stats.uniqueSources.toLocaleString()}</strong>
        </article>
      </section>

      <section className="event-log-chart-card event-log-card">
        <div className="event-log-section-title">
          <div>
            <p>Bar Chart</p>
            <h3>막대그래프</h3>
          </div>

          <select value={chartKey} onChange={(e) => setChartKey(e.target.value)}>
            {CHART_OPTIONS.map((item) => (
              <option key={item.key} value={item.key}>
                {item.label}
              </option>
            ))}
          </select>
        </div>

        <BarChart rows={chartRows} />
      </section>

      <section className="event-log-panel event-log-card">
        <div className="event-log-section-title">
          <div>
            <p>Table</p>
            <h3>로그 목록</h3>
          </div>

          <span className="event-log-count">
            {displayRows.length.toLocaleString()} /{' '}
            {clientFilteredLogs.length.toLocaleString()}건
          </span>
        </div>

        <div className="event-log-table-wrap">
          <table className="event-log-table">
            <thead>
              <tr>
                <th>시간</th>
                <th>이벤트</th>
                <th>인터페이스</th>
                <th>프로토콜</th>
                <th>출발지</th>
                <th>목적지</th>
                <th>룰/시그니처</th>
                <th>심각도</th>
                <th>상세</th>
              </tr>
            </thead>

            <tbody>
              {displayRows.length === 0 ? (
                <tr>
                  <td colSpan="9" className="event-log-empty">
                    표시할 로그가 없습니다.
                  </td>
                </tr>
              ) : (
                displayRows.map((log, index) => (
                  <tr key={log.id || index}>
                    <td>{toText(log.timestamp)}</td>
                    <td>{toText(normalizeEventType(log))}</td>
                    <td>{toText(log.interface)}</td>
                    <td>{toText(normalizeProtocol(log))}</td>
                    <td>
                      {toText(log.source_ip)}
                      {log.source_port && log.source_port !== '-'
                        ? `:${log.source_port}`
                        : ''}
                    </td>
                    <td>
                      {toText(log.destination_ip)}
                      {log.destination_port && log.destination_port !== '-'
                        ? `:${log.destination_port}`
                        : ''}
                    </td>
                    <td>{toText(log.rule)}</td>
                    <td>{toText(log.severity)}</td>
                    <td>
                      <button
                        type="button"
                        className="event-log-detail-button"
                        onClick={() => setSelectedLog(log)}
                      >
                        보기
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <EventDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  )
}

export default FirewallEventLogsPage
