import { useEffect, useMemo, useRef, useState } from 'react'
import '../styles/logCsvExport.css'
import {
  OPN_LOG_EXPORT_COLUMNS,
  buildOpnsenseExportRows,
  downloadCsv,
  makeTimestampedFilename,
} from '../utils/logCsvExport'

const REFRESH_INTERVAL_MS = 30000

const DEFAULT_FILTERS = {
  quickSearch: '',
  filterField: 'any',
  operator: 'contains',
  filterValue: '',
  tableSize: 25,
  historySize: 300,
  autoRefresh: false,
  resolveHostnames: false,
  onlyImportant: false,
  preset: '',
}

const TABLE_SIZE_OPTIONS = [25, 50, 100]
const HISTORY_SIZE_OPTIONS = [100, 200, 300]

const toText = (value, fallback = '-') => {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

const actionClassName = (action) => {
  const text = String(action || '').toLowerCase()

  if (text.includes('pass') || text.includes('allow')) return 'pass'
  if (text.includes('block') || text.includes('deny') || text.includes('drop')) return 'block'
  if (text.includes('reject')) return 'reject'

  return 'unknown'
}

function LogDetailModal({ log, onClose }) {
  if (!log) return null

  return (
    <div className="opn-log-modal-backdrop" onClick={onClose}>
      <div className="opn-log-modal" onClick={(e) => e.stopPropagation()}>
        <div className="opn-log-modal-header">
          <div>
            <p className="opn-log-eyebrow">Log Detail</p>
            <h3>추가 정보</h3>
          </div>
          <button type="button" onClick={onClose}>닫기</button>
        </div>

        <div className="opn-log-modal-summary">
          <span>시간: {toText(log.time)}</span>
          <span>Action: {toText(log.action)}</span>
          <span>출발지: {toText(log.source)}</span>
          <span>목적지: {toText(log.destination)}</span>
        </div>

        <pre className="opn-log-modal-pre">
          {JSON.stringify(log.raw || log, null, 2)}
        </pre>
      </div>
    </div>
  )
}

function OpnsenseFirewallLogsPage({ selectedFirewall, fetchOpnsenseLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [selectedLog, setSelectedLog] = useState(null)
  const loadingRef = useRef(false)
  const requestSeqRef = useRef(0)

  const selectedName = selectedFirewall?.name || '없음'

  const visibleLogs = useMemo(() => {
    return logs.slice(0, Number(filters.tableSize) || 25)
  }, [logs, filters.tableSize])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setFilters((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  const loadLogs = async ({ silent = false } = {}) => {
    if (!selectedFirewall || loadingRef.current) return

    const seq = requestSeqRef.current + 1
    requestSeqRef.current = seq

    try {
      loadingRef.current = true
      if (!silent) setLoading(true)
      setError('')

      const safeHistorySize = Math.min(Number(filters.historySize) || 300, 300)

      const data = await fetchOpnsenseLogs({
        search: filters.quickSearch || filters.filterValue || '',
        field: filters.filterField,
        operator: filters.operator,
        tableSize: safeHistorySize,
        historySize: safeHistorySize,
        resolveHostnames: false,
        onlyImportant: filters.onlyImportant,
      })

      if (seq !== requestSeqRef.current) return
      setLogs(Array.isArray(data?.rows) ? data.rows : [])
    } catch (err) {
      if (seq !== requestSeqRef.current) return
      setLogs([])
      setError(err.message || 'OPNsense 로그 조회 실패')
    } finally {
      loadingRef.current = false
      if (!silent) setLoading(false)
    }
  }

  const handleExportCsv = () => {
    downloadCsv(
      makeTimestampedFilename('opnsense_live_logs'),
      OPN_LOG_EXPORT_COLUMNS,
      buildOpnsenseExportRows(logs),
    )
  }

  useEffect(() => {
    loadLogs()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall])

  useEffect(() => {
    if (!filters.autoRefresh || !selectedFirewall) return

    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadLogs({ silent: true })
      }
    }, REFRESH_INTERVAL_MS)

    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    filters.autoRefresh,
    selectedFirewall,
    filters.historySize,
    filters.quickSearch,
    filters.filterValue,
  ])

  return (
    <div className="opn-log-page">
      <section className="opn-log-header">
        <div>
          <p className="opn-log-eyebrow">OPNsense Live Firewall Logs</p>
          <h2>OPNsense 실시간 로그</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className="opn-log-actions">
          <button type="button" onClick={() => loadLogs()} disabled={loading}>
            {loading ? '조회 중...' : '조회'}
          </button>

          <button
            type="button"
            className="csv"
            onClick={handleExportCsv}
            disabled={logs.length === 0}
          >
            CSV 내보내기
          </button>
        </div>
      </section>

      {error ? <div className="opn-log-error">에러: {error}</div> : null}

      <section className="opn-log-filter-card">
        <div className="opn-log-filter-grid">
          <label>
            검색어
            <input
              name="quickSearch"
              value={filters.quickSearch}
              onChange={handleChange}
              placeholder="IP, action, label..."
              onKeyDown={(e) => {
                if (e.key === 'Enter') loadLogs()
              }}
            />
          </label>

          <label>
            조회 범위
            <select
              name="historySize"
              value={filters.historySize}
              onChange={handleChange}
            >
              {HISTORY_SIZE_OPTIONS.map((value) => (
                <option key={value} value={value}>
                  {value}개
                </option>
              ))}
            </select>
          </label>

          <label>
            화면 표시
            <select
              name="tableSize"
              value={filters.tableSize}
              onChange={handleChange}
            >
              {TABLE_SIZE_OPTIONS.map((value) => (
                <option key={value} value={value}>
                  {value}개
                </option>
              ))}
            </select>
          </label>

          <label>
            중요 로그만
            <select
              name="onlyImportant"
              value={filters.onlyImportant ? '1' : '0'}
              onChange={(e) =>
                setFilters((prev) => ({
                  ...prev,
                  onlyImportant: e.target.value === '1',
                }))
              }
            >
              <option value="0">전체</option>
              <option value="1">중요 로그</option>
            </select>
          </label>

          <label>
            자동 새로고침
            <select
              name="autoRefresh"
              value={filters.autoRefresh ? '1' : '0'}
              onChange={(e) =>
                setFilters((prev) => ({
                  ...prev,
                  autoRefresh: e.target.value === '1',
                }))
              }
            >
              <option value="0">꺼짐</option>
              <option value="1">30초</option>
            </select>
          </label>
        </div>
      </section>

      <section className="opn-log-table-panel">
        <div className="opn-log-table-wrap">
          <table className="opn-log-table">
            <thead>
              <tr>
                <th>시간</th>
                <th>인터페이스</th>
                <th>방향</th>
                <th>프로토콜</th>
                <th>출발지</th>
                <th>목적지</th>
                <th>Action</th>
                <th>Label</th>
                <th>자세히 보기</th>
              </tr>
            </thead>

            <tbody>
              {visibleLogs.length === 0 ? (
                <tr>
                  <td colSpan="9" className="opn-log-empty">
                    표시할 로그가 없습니다.
                  </td>
                </tr>
              ) : (
                visibleLogs.map((log, index) => {
                  const rowId = log.id || `opn-${index}`
                  const actionStyle = actionClassName(log.action)

                  return (
                    <tr key={rowId}>
                      <td>{toText(log.time)}</td>
                      <td>{toText(log.interface)}</td>
                      <td>{toText(log.direction)}</td>
                      <td>{toText(log.protocol)}</td>
                      <td>{toText(log.source)}</td>
                      <td>{toText(log.destination)}</td>
                      <td>
                        <span className={`opn-log-action-badge ${actionStyle}`}>
                          {toText(log.action)}
                        </span>
                      </td>
                      <td>{toText(log.label)}</td>
                      <td>
                        <button
                          type="button"
                          className="opn-log-detail-button"
                          onClick={() => setSelectedLog(log)}
                        >
                          자세히 보기
                        </button>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      <LogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  )
}

export default OpnsenseFirewallLogsPage
