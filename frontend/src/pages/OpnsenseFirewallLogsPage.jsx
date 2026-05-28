import { useEffect, useMemo, useRef, useState } from 'react'

const DEFAULT_FILTERS = {
  quickSearch: '',
  filterField: 'action',
  operator: 'contains',
  filterValue: '',
  tableSize: 25,
  historySize: 10000,
  autoRefresh: true,
  resolveHostnames: false,
  onlyImportant: false,
  preset: '',
}

const REFRESH_INTERVAL_MS = 10000

const PRESETS = {
  block: {
    label: 'Block 로그',
    filterField: 'action',
    operator: 'equals',
    filterValue: 'block',
    onlyImportant: false,
  },
  pass: {
    label: 'Pass 로그',
    filterField: 'action',
    operator: 'equals',
    filterValue: 'pass',
    onlyImportant: false,
  },
  wanBlock: {
    label: 'WAN Block',
    filterField: 'combined',
    operator: 'contains',
    filterValue: 'em0 block',
    onlyImportant: false,
  },
  lanPass: {
    label: 'LAN Pass',
    filterField: 'combined',
    operator: 'contains',
    filterValue: 'em1 pass',
    onlyImportant: false,
  },
  tcp: {
    label: 'TCP',
    filterField: 'protocol',
    operator: 'equals',
    filterValue: 'tcp',
    onlyImportant: false,
  },
  udp: {
    label: 'UDP',
    filterField: 'protocol',
    operator: 'equals',
    filterValue: 'udp',
    onlyImportant: false,
  },
  dns: {
    label: 'DNS',
    filterField: 'combined',
    operator: 'contains',
    filterValue: ':53',
    onlyImportant: false,
  },
  antiLockout: {
    label: 'Anti-lockout rule',
    filterField: 'label',
    operator: 'contains',
    filterValue: 'anti-lockout',
    onlyImportant: false,
  },
}

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

  const direction =
    item.direction || item.dir || src.direction || src.dir || '-'

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

  const action = item.action || item.act || src.action || src.act || '-'

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
    interface: toDisplayText(interfaceName),
    direction: toDisplayText(direction),
    time: toDisplayText(time),
    protocol: toDisplayText(protocol).toLowerCase(),
    source: normalizeAddress(sourceIp, sourcePort),
    destination: normalizeAddress(destinationIp, destinationPort),
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

const getCombinedText = (log) => {
  return [
    log.interface,
    log.direction,
    log.time,
    log.protocol,
    log.source,
    log.destination,
    log.action,
    log.label,
  ]
    .map((item) => toDisplayText(item, ''))
    .join(' ')
    .toLowerCase()
}

const getFieldValue = (log, field) => {
  if (field === 'combined' || field === 'any') return getCombinedText(log)

  return toDisplayText(log[field], '').toLowerCase()
}

const matchByOperator = (value, keyword, operator) => {
  const text = toDisplayText(value, '').toLowerCase()
  const target = toDisplayText(keyword, '').toLowerCase().trim()

  if (!target) return true

  if (operator === 'equals') return text === target
  if (operator === 'startsWith') return text.startsWith(target)
  if (operator === 'endsWith') return text.endsWith(target)

  return text.includes(target)
}

function InfoIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M11 10h2v7h-2v-7zm0-3h2v2h-2V7z" />
      <path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm0 18a8 8 0 1 1 0-16 8 8 0 0 1 0 16z" />
    </svg>
  )
}

function OpnsenseFirewallLogsPage({ selectedFirewall, fetchOpnsenseLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [logs, setLogs] = useState([])
  const [loading, setLoading] = useState(false)
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)
  const [error, setError] = useState('')
  const [selectedLog, setSelectedLog] = useState(null)

  const timerRef = useRef(null)
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'

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
        search: filters.quickSearch || filters.filterValue || '',
        field: filters.filterField,
        operator: filters.operator,
        tableSize: filters.historySize,
        historySize: filters.historySize,
        resolveHostnames: filters.resolveHostnames,
        onlyImportant: filters.onlyImportant,
      })

      setLogs(normalizeLogs(data))
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err.message || 'OPNsense 방화벽 로그 조회에 실패했습니다.')
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
  }, [
    filters.autoRefresh,
    filters.historySize,
    selectedFirewall,
    filters.quickSearch,
    filters.filterValue,
    filters.filterField,
    filters.operator,
    filters.onlyImportant,
  ])

  const filteredLogs = useMemo(() => {
    const quickKeyword = filters.quickSearch.trim()
    const conditionKeyword = filters.filterValue.trim()

    return logs.filter((log) => {
      if (filters.onlyImportant && log.action !== 'block') {
        return false
      }

      if (
        quickKeyword &&
        !matchByOperator(getCombinedText(log), quickKeyword, 'contains')
      ) {
        return false
      }

      if (conditionKeyword) {
        const value = getFieldValue(log, filters.filterField)

        if (!matchByOperator(value, conditionKeyword, filters.operator)) {
          return false
        }
      }

      return true
    })
  }, [logs, filters])

  const visibleLogs = useMemo(() => {
    return filteredLogs.slice(0, filters.tableSize)
  }, [filteredLogs, filters.tableSize])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target

    setFilters((prev) => ({
      ...prev,
      [name]:
        type === 'checkbox'
          ? checked
          : name === 'tableSize' || name === 'historySize'
            ? Number(value)
            : value,
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    await loadLogs()
  }

  const handleResetSearch = () => {
    setFilters((prev) => ({
      ...prev,
      quickSearch: '',
      filterField: 'action',
      operator: 'contains',
      filterValue: '',
      preset: '',
      onlyImportant: false,
    }))
  }

  const handlePresetChange = (e) => {
    const presetKey = e.target.value
    const preset = PRESETS[presetKey]

    if (!preset) {
      setFilters((prev) => ({
        ...prev,
        preset: '',
      }))
      return
    }

    setFilters((prev) => ({
      ...prev,
      preset: presetKey,
      filterField: preset.filterField,
      operator: preset.operator,
      filterValue: preset.filterValue,
      onlyImportant: preset.onlyImportant,
    }))
  }

  const exportVisibleLogs = () => {
    const columns = [
      ['interface', '인터페이스'],
      ['direction', '방향'],
      ['time', '시간'],
      ['protocol', '프로토콜'],
      ['source', '출발지'],
      ['destination', '목적지'],
      ['action', '작업'],
      ['label', '라벨'],
    ]

    const escapeCsv = (value) => {
      const text = toDisplayText(value, '').replaceAll('"', '""')
      return /[",\n\r]/.test(text) ? `"${text}"` : text
    }

    const csvRows = [
      columns.map(([, label]) => escapeCsv(label)).join(','),
      ...visibleLogs.map((log) =>
        columns.map(([key]) => escapeCsv(log[key])).join(','),
      ),
    ]

    const blob = new Blob(['\uFEFF' + csvRows.join('\n')], {
      type: 'text/csv;charset=utf-8;',
    })

    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    const now = new Date().toISOString().slice(0, 19).replaceAll(':', '-')

    link.href = url
    link.download = `opnsense-live-logs-${now}.csv`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="opn-log-page">
      <section className="opn-log-title-panel">
        <div>
          <p className="opn-log-eyebrow">OPNsense Live Firewall Log</p>
          <h2>방화벽 로그 파일: 실시간 보기</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className={`opn-log-status ${loading ? 'loading' : 'ready'}`}>
          <i />
          {loading ? '로그 갱신 중' : '실시간 수집 대기 중'}
        </div>
      </section>

      <section className="opn-log-control-panel opn-log-control-modern">
        <form
          className="opn-log-card opn-log-filter-area"
          onSubmit={handleSubmit}
        >
          <div className="opn-log-card-header">
            <div>
              <p>Filter</p>
              <h3>로그 검색</h3>
            </div>
            <button type="button" onClick={() => loadLogs()}>
              갱신
            </button>
          </div>

          <div className="opn-log-form-grid">
            <label className="opn-log-field opn-log-field-wide">
              <span>Quick search</span>
              <input
                name="quickSearch"
                value={filters.quickSearch}
                onChange={handleChange}
                placeholder="전체 필드 검색..."
              />
            </label>

            <label className="opn-log-field">
              <span>필드</span>
              <select
                name="filterField"
                value={filters.filterField}
                onChange={handleChange}
              >
                <option value="combined">전체</option>
                <option value="interface">인터페이스</option>
                <option value="direction">방향</option>
                <option value="protocol">프로토콜</option>
                <option value="source">출발지</option>
                <option value="destination">목적지</option>
                <option value="action">작업</option>
                <option value="label">라벨</option>
              </select>
            </label>

            <label className="opn-log-field">
              <span>조건</span>
              <select
                name="operator"
                value={filters.operator}
                onChange={handleChange}
              >
                <option value="contains">포함</option>
                <option value="equals">일치</option>
                <option value="startsWith">시작</option>
                <option value="endsWith">끝</option>
              </select>
            </label>

            <label className="opn-log-field opn-log-field-wide">
              <span>검색어</span>
              <input
                name="filterValue"
                value={filters.filterValue}
                onChange={handleChange}
                placeholder="예: block, pass, em0, 192.168..."
              />
            </label>
          </div>

          <div className="opn-log-actions">
            <button type="submit" className="opn-log-primary-btn">
              적용
            </button>
            <button type="button" onClick={handleResetSearch}>
              초기화
            </button>
            <button type="button" onClick={exportVisibleLogs}>
              CSV 내보내기
            </button>
          </div>

          <div className="opn-log-active-filter">
            Active filters:{' '}
            {filters.quickSearch || filters.filterValue || filters.onlyImportant
              ? [
                  filters.quickSearch ? `quick="${filters.quickSearch}"` : '',
                  filters.filterValue
                    ? `${filters.filterField} ${filters.operator} "${filters.filterValue}"`
                    : '',
                  filters.onlyImportant ? 'block only' : '',
                ]
                  .filter(Boolean)
                  .join(' / ')
              : '-'}
          </div>
        </form>

        <section className="opn-log-card opn-log-template-area">
          <div className="opn-log-card-header">
            <div>
              <p>Preset</p>
              <h3>프리셋</h3>
            </div>
          </div>

          <label className="opn-log-field">
            <span>템플릿 선택</span>
            <select
              name="preset"
              value={filters.preset}
              onChange={handlePresetChange}
            >
              <option value="">Choose template</option>
              {Object.entries(PRESETS).map(([key, preset]) => (
                <option key={key} value={key}>
                  {preset.label}
                </option>
              ))}
            </select>
          </label>

          <button
            type="button"
            className="opn-log-template-clear"
            onClick={() =>
              setFilters((prev) => ({
                ...prev,
                preset: '',
                filterField: 'action',
                operator: 'contains',
                filterValue: '',
              }))
            }
          >
            프리셋 해제
          </button>

          <div className="opn-log-last-updated">
            마지막 갱신:{' '}
            {lastUpdatedAt ? lastUpdatedAt.toLocaleTimeString() : '-'}
          </div>
        </section>

        <section className="opn-log-card opn-log-option-area">
          <div className="opn-log-card-header">
            <div>
              <p>Options</p>
              <h3>표시 설정</h3>
            </div>
          </div>

          <label className="opn-log-check">
            <input
              type="checkbox"
              name="autoRefresh"
              checked={filters.autoRefresh}
              onChange={handleChange}
            />
            <span>Auto-refresh</span>
          </label>

          <label className="opn-log-check disabled">
            <input
              type="checkbox"
              name="resolveHostnames"
              checked={filters.resolveHostnames}
              onChange={handleChange}
              disabled
            />
            <span>호스트 이름 조회 준비 중</span>
          </label>

          <label className="opn-log-check">
            <input
              type="checkbox"
              name="onlyImportant"
              checked={filters.onlyImportant}
              onChange={handleChange}
            />
            <span>Block 로그만 보기</span>
          </label>

          <label className="opn-log-field">
            <span>Table size</span>
            <select
              name="tableSize"
              value={filters.tableSize}
              onChange={handleChange}
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={200}>200</option>
            </select>
          </label>

          <label className="opn-log-field">
            <span>History size</span>
            <select
              name="historySize"
              value={filters.historySize}
              onChange={handleChange}
            >
              <option value={100}>100</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
              <option value={5000}>5000</option>
              <option value={10000}>10000</option>
            </select>
          </label>
        </section>
      </section>

      {error ? <div className="opn-log-error">{error}</div> : null}

      <section className="opn-log-table-panel">
        <div className="opn-log-table-summary">
          <span>전체 {logs.length}건</span>
          <span>필터 결과 {filteredLogs.length}건</span>
          <span>표시 {visibleLogs.length}건</span>
        </div>

        <div className="opn-log-table-wrap">
          <table className="opn-log-table">
            <thead>
              <tr>
                <th>인터페이스</th>
                <th>방향</th>
                <th>시간</th>
                <th>프로토콜</th>
                <th>출발지</th>
                <th>목적지</th>
                <th>작업</th>
                <th>라벨</th>
                <th>상세</th>
              </tr>
            </thead>

            <tbody>
              {visibleLogs.length === 0 ? (
                <tr>
                  <td colSpan="9" className="opn-log-empty">
                    {loading
                      ? '로그를 불러오는 중입니다.'
                      : '표시할 로그가 없습니다.'}
                  </td>
                </tr>
              ) : (
                visibleLogs.map((log) => (
                  <tr key={log.id} className={`opn-log-row ${log.action}`}>
                    <td>{log.interface}</td>
                    <td>{log.direction}</td>
                    <td>{formatTime(log.time)}</td>
                    <td>{log.protocol}</td>
                    <td>{log.source}</td>
                    <td>{log.destination}</td>
                    <td>{log.action}</td>
                    <td>{log.label}</td>
                    <td>
                      <button
                        type="button"
                        className="opn-log-info-btn"
                        onClick={() => setSelectedLog(log)}
                        aria-label="로그 상세 정보 보기"
                      >
                        <InfoIcon />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      {selectedLog ? (
        <div
          className="opn-log-modal-backdrop"
          onClick={() => setSelectedLog(null)}
        >
          <div className="opn-log-modal" onClick={(e) => e.stopPropagation()}>
            <div className="opn-log-modal-header">
              <h3>로그 상세 정보</h3>
              <button type="button" onClick={() => setSelectedLog(null)}>
                ×
              </button>
            </div>

            <pre>{JSON.stringify(selectedLog.raw || selectedLog, null, 2)}</pre>
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default OpnsenseFirewallLogsPage
