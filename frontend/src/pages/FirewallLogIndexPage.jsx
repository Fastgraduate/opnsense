import { useEffect, useMemo, useRef, useState } from 'react'
import '../styles/logCsvExport.css'
import {
  KIBANA_EXPORT_COLUMNS,
  buildElasticExportRows,
  downloadCsv,
  makeTimestampedFilename,
} from '../utils/logCsvExport'

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

  if (otherCount > 0) top.push({ label: '기타', count: otherCount })

  return top
}

function BarChart({ rows, classPrefix }) {
  const max = Math.max(...rows.map((row) => row.count), 1)

  if (!rows.length) {
    return (
      <div className={`${classPrefix}-chart-empty`}>
        차트로 표시할 데이터가 없습니다.
      </div>
    )
  }

  return (
    <div className={`${classPrefix}-bar-chart`}>
      {rows.map((row, index) => {
        const percent = Math.max((row.count / max) * 100, 3)

        return (
          <div key={`${row.label}-${index}`} className={`${classPrefix}-bar-row`}>
            <div className={`${classPrefix}-bar-label`} title={row.label}>
              {row.label}
            </div>
            <div className={`${classPrefix}-bar-track`}>
              <div
                className={`${classPrefix}-bar-fill`}
                style={{ width: `${percent}%` }}
              />
            </div>
            <div className={`${classPrefix}-bar-count`}>
              {row.count.toLocaleString()}건
            </div>
          </div>
        )
      })}
    </div>
  )
}

function LogDetailModal({ log, onClose, title = '로그 상세' }) {
  if (!log) return null

  return (
    <div className="event-log-modal-backdrop" onClick={onClose}>
      <div className="event-log-modal" onClick={(e) => e.stopPropagation()}>
        <div className="event-log-modal-header">
          <div>
            <p className="event-log-eyebrow">Log Detail</p>
            <h3>{title}</h3>
          </div>
          <button type="button" onClick={onClose}>닫기</button>
        </div>

        <div className="event-log-modal-summary">
          <span>시간: {toText(log.timestamp)}</span>
          <span>이벤트: {toText(normalizeEventType(log))}</span>
          <span>인터페이스: {toText(log.interface)}</span>
          <span>출발지: {toText(log.source_ip)}:{toText(log.source_port, '')}</span>
          <span>목적지: {toText(log.destination_ip)}:{toText(log.destination_port, '')}</span>
        </div>

        <pre className="event-log-modal-pre">
          {JSON.stringify(log.raw || log, null, 2)}
        </pre>
      </div>
    </div>
  )
}

const DEFAULT_FILTERS = {
  minutes: 1440,
  size: 300,
  action: '',
  interface: '',
  query: '',
  eventType: '',
  protocol: '',
}

const PRESETS = [
  {
    key: 'recent',
    label: '최근 24시간',
    description: '최근 24시간 로그 인덱싱',
    filters: { minutes: 1440, size: 300, action: '', interface: '', query: '', eventType: '', protocol: '' },
  },
  {
    key: 'alert',
    label: 'Alert 인덱스',
    description: 'Alert 이벤트만 집계',
    filters: { minutes: 1440, size: 300, action: 'alert', eventType: 'alert', query: '' },
  },
  {
    key: 'flow',
    label: 'Flow 인덱스',
    description: 'Flow 이벤트만 집계',
    filters: { minutes: 360, size: 300, action: 'flow', eventType: 'flow', query: '' },
  },
  {
    key: 'dns',
    label: 'DNS',
    description: 'DNS 관련 이벤트',
    filters: { minutes: 1440, size: 300, action: '', eventType: 'dns', query: 'dns' },
  },
  {
    key: 'http',
    label: 'HTTP',
    description: 'HTTP 관련 이벤트',
    filters: { minutes: 1440, size: 300, action: '', eventType: 'http', query: 'http' },
  },
  {
    key: 'important',
    label: '중요 로그',
    description: 'alert/drop/block/deny 중심',
    filters: { minutes: 1440, size: 300, action: '', eventType: '', query: 'alert drop block deny' },
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

function FirewallLogIndexPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [activePreset, setActivePreset] = useState('recent')
  const [chartKey, setChartKey] = useState('event_type')
  const [logs, setLogs] = useState([])
  const [exportColumns, setExportColumns] = useState(KIBANA_EXPORT_COLUMNS)
  const [selectedLog, setSelectedLog] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'

  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (filters.eventType && !includesText(normalizeEventType(log), filters.eventType)) return false
      if (filters.protocol && !includesText(normalizeProtocol(log), filters.protocol)) return false
      return true
    })
  }, [logs, filters.eventType, filters.protocol])

  const chartRows = useMemo(() => buildChartRows(filteredLogs, chartKey), [filteredLogs, chartKey])

  const indexRows = useMemo(() => {
    const byType = buildChartRows(filteredLogs, 'event_type')
    const byInterface = buildChartRows(filteredLogs, 'interface')
    const byProtocol = buildChartRows(filteredLogs, 'protocol')

    return [
      ...byType.map((row) => ({ group: '이벤트 타입', ...row })),
      ...byInterface.map((row) => ({ group: '인터페이스', ...row })),
      ...byProtocol.map((row) => ({ group: '프로토콜', ...row })),
    ]
  }, [filteredLogs])

  const stats = useMemo(() => {
    const total = filteredLogs.length
    const alert = filteredLogs.filter((row) => lower(normalizeEventType(row)) === 'alert').length
    const flow = filteredLogs.filter((row) => lower(normalizeEventType(row)) === 'flow').length
    const uniqueIndex = new Set(filteredLogs.map((row) => row?.exportRow?._index || row?.raw?._index || row?.raw?.['_index']).filter(Boolean)).size
    return { total, alert, flow, uniqueIndex }
  }, [filteredLogs])

  const handleChange = (e) => {
    const { name, value } = e.target
    setActivePreset('custom')
    setFilters((prev) => ({ ...prev, [name]: value }))
  }

  const applyPreset = (preset) => {
    setActivePreset(preset.key)
    setFilters((prev) => ({ ...prev, ...preset.filters }))
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
        size: Math.min(Number(filters.size) || 300, 300),
        minutes: Number(filters.minutes) || 1440,
        action: filters.action,
        interface: filters.interface,
        query: filters.query,
      })

      setLogs(Array.isArray(data?.rows) ? data.rows : [])
      setExportColumns(Array.isArray(data?.exportColumns) && data.exportColumns.length > 0 ? data.exportColumns : KIBANA_EXPORT_COLUMNS)
    } catch (err) {
      setLogs([])
      setError(err.message || '로그 인덱싱 조회 실패')
    } finally {
      loadingRef.current = false
      setLoading(false)
    }
  }

  const handleExportCsv = () => {
    downloadCsv(makeTimestampedFilename('kibana_index_logs'), exportColumns, buildElasticExportRows(filteredLogs))
  }

  useEffect(() => {
    loadLogs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall])

  return (
    <div className="log-index-page">
      <section className="log-index-header log-index-card">
        <div>
          <p className="log-index-eyebrow">Elastic Log Index</p>
          <h2>로그 인덱싱</h2>
          <span>현재 대상: {selectedName}</span>
        </div>
        <div className="log-index-actions">
          <button type="button" onClick={loadLogs} disabled={loading}>{loading ? '조회 중...' : '조회'}</button>
          <button type="button" className="csv" onClick={handleExportCsv} disabled={filteredLogs.length === 0}>CSV 내보내기</button>
        </div>
      </section>

      {error ? <div className="log-index-error">에러: {error}</div> : null}

      <section className="log-index-card">
        <div className="log-index-section-title">
          <div><p>Presets</p><h3>프리셋</h3></div>
          <button type="button" onClick={resetFilters}>초기화</button>
        </div>
        <div className="log-index-preset-grid">
          {PRESETS.map((preset) => (
            <button key={preset.key} type="button" className={activePreset === preset.key ? 'active' : ''} onClick={() => applyPreset(preset)}>
              <strong>{preset.label}</strong>
              <span>{preset.description}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="log-index-filter-card log-index-card">
        <div className="log-index-section-title"><div><p>Filters</p><h3>필터</h3></div></div>
        <div className="log-index-filter-grid expanded">
          <label>조회 범위<select name="minutes" value={filters.minutes} onChange={handleChange}><option value="60">최근 1시간</option><option value="360">최근 6시간</option><option value="1440">최근 24시간</option></select></label>
          <label>조회 개수<select name="size" value={filters.size} onChange={handleChange}><option value="100">100개</option><option value="200">200개</option><option value="300">300개</option></select></label>
          <label>서버 Action/Event<input name="action" value={filters.action} onChange={handleChange} placeholder="alert, flow..." /></label>
          <label>서버 Interface<input name="interface" value={filters.interface} onChange={handleChange} placeholder="ens33..." /></label>
          <label>서버 검색어<input name="query" value={filters.query} onChange={handleChange} onKeyDown={(e) => { if (e.key === 'Enter') loadLogs() }} /></label>
          <label>이벤트 타입<input name="eventType" value={filters.eventType} onChange={handleChange} /></label>
          <label>프로토콜<input name="protocol" value={filters.protocol} onChange={handleChange} /></label>
        </div>
      </section>

      <section className="log-index-stats-grid">
        <article className="log-index-stat-card"><span>총 로그</span><strong>{stats.total.toLocaleString()}</strong></article>
        <article className="log-index-stat-card"><span>Alert</span><strong>{stats.alert.toLocaleString()}</strong></article>
        <article className="log-index-stat-card"><span>Flow</span><strong>{stats.flow.toLocaleString()}</strong></article>
        <article className="log-index-stat-card"><span>Index</span><strong>{stats.uniqueIndex.toLocaleString()}</strong></article>
      </section>

      <section className="log-index-card">
        <div className="log-index-section-title">
          <div><p>Bar Chart</p><h3>인덱싱 분포</h3></div>
          <select value={chartKey} onChange={(e) => setChartKey(e.target.value)}>{CHART_OPTIONS.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}</select>
        </div>
        <BarChart rows={chartRows} classPrefix="log-index" />
      </section>

      <section className="log-index-card">
        <div className="log-index-section-title">
          <div><p>Index Table</p><h3>인덱싱 요약</h3></div>
          <span className="log-index-count">{indexRows.length.toLocaleString()}개 항목</span>
        </div>
        <div className="log-index-table-wrap">
          <table className="log-index-table">
            <thead><tr><th>구분</th><th>항목</th><th>건수</th></tr></thead>
            <tbody>
              {indexRows.length === 0 ? <tr><td colSpan="3" className="log-index-empty">표시할 데이터가 없습니다.</td></tr> : indexRows.map((row, index) => (
                <tr key={`${row.group}-${row.label}-${index}`}><td>{row.group}</td><td>{row.label}</td><td>{row.count.toLocaleString()}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} title="로그 인덱싱 상세" />
    </div>
  )
}

export default FirewallLogIndexPage
