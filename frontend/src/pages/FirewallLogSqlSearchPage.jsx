import { Fragment, useMemo, useState } from 'react'

const DEFAULT_FILTERS = {
  size: 500,
  minutes: 0,
  action: '',
  interface: '',
  query: '',
}

const EXPAND_ANIMATION_MS = 240

const getNested = (obj, path, fallback = '') => {
  if (!obj || !path) return fallback

  const value = path.split('.').reduce((acc, key) => {
    if (acc && typeof acc === 'object' && key in acc) return acc[key]
    return undefined
  }, obj)

  return value ?? fallback
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

const formatDateTime = (value) => {
  if (!value || value === '-') return '-'

  try {
    return new Date(value).toLocaleString('ko-KR', { hour12: false })
  } catch {
    return toDisplayText(value)
  }
}

const flattenObject = (obj, prefix = '') => {
  if (!obj || typeof obj !== 'object') return []

  return Object.entries(obj).flatMap(([key, value]) => {
    const nextKey = prefix ? `${prefix}.${key}` : key

    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      !(value instanceof Date)
    ) {
      return flattenObject(value, nextKey)
    }

    return [
      {
        field: nextKey,
        value,
      },
    ]
  })
}

const buildDetailSource = (row) => {
  return {
    _id: row.elastic_id || row.id,
    _index: row.elastic_index || '-',
    _score: row.elastic_score ?? '-',
    _type: row.elastic_type || '_doc',
    '@timestamp': row.timestamp,
    action: row.action,
    interface: row.interface,
    protocol: row.protocol,
    source: {
      ip: row.source_ip,
      port: row.source_port,
    },
    destination: {
      ip: row.destination_ip,
      port: row.destination_port,
    },
    rule: row.rule,
    severity: row.severity,
    category: row.category,
    host: row.host,
    event_type: row.event_type,
    raw: row.raw,
  }
}

function EventLogDetail({ row, activeTab, setActiveTab }) {
  const [copied, setCopied] = useState(false)

  const detailSource = useMemo(() => buildDetailSource(row), [row])
  const flattenedRows = useMemo(() => flattenObject(detailSource), [detailSource])
  const jsonText = useMemo(
    () => JSON.stringify(detailSource, null, 2),
    [detailSource],
  )

  const handleCopyJson = async () => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(jsonText)
      } else {
        const textarea = document.createElement('textarea')
        textarea.value = jsonText
        document.body.appendChild(textarea)
        textarea.select()
        document.execCommand('copy')
        document.body.removeChild(textarea)
      }

      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      alert('클립보드 복사에 실패했습니다.')
    }
  }

  return (
    <div className="event-expanded-document">
      <div className="event-expanded-title-row">
        <div>
          <div className="event-expanded-title">
            <span className="event-expanded-folder">▱</span>
            Expanded document
          </div>
          <div className="event-expanded-subtitle">
            {toDisplayText(row.elastic_index || row.id)}
          </div>
        </div>
      </div>

      <div className="event-detail-tabs">
        <button
          type="button"
          className={activeTab === 'table' ? 'active' : ''}
          onClick={() => setActiveTab('table')}
        >
          Table
        </button>

        <button
          type="button"
          className={activeTab === 'json' ? 'active' : ''}
          onClick={() => setActiveTab('json')}
        >
          JSON
        </button>
      </div>

      {activeTab === 'table' ? (
        <div className="event-detail-table-wrap">
          <table className="event-detail-table">
            <thead>
              <tr>
                <th>Actions</th>
                <th>Field</th>
                <th>Value</th>
              </tr>
            </thead>

            <tbody>
              {flattenedRows.map((item) => (
                <tr key={item.field}>
                  <td>
                    <span className="event-field-action-dot">t</span>
                  </td>
                  <td>
                    <span className="event-field-name">{item.field}</span>
                  </td>
                  <td>
                    <span className="event-field-value">
                      {toDisplayText(item.value)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="event-json-panel">
          <div className="event-json-toolbar">
            <span>Raw JSON</span>

            <button
              type="button"
              className="event-copy-json-btn"
              onClick={handleCopyJson}
            >
              {copied ? '복사 완료' : 'JSON 복사'}
            </button>
          </div>

          <pre>{jsonText}</pre>
        </div>
      )}
    </div>
  )
}

function FirewallLogSqlSearchPage({ selectedFirewall, fetchEventLogs }) {
  const [query, setQuery] = useState(
    "SELECT * FROM logs WHERE source_ip = '192.168.0.2'",
  )
  const [rows, setRows] = useState([])
  const [resultRows, setResultRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [expandedRowId, setExpandedRowId] = useState(null)
  const [closingRowId, setClosingRowId] = useState(null)
  const [detailTab, setDetailTab] = useState('table')

  const selectedName = selectedFirewall?.name || '없음'

  const closeExpandedImmediately = () => {
    setExpandedRowId(null)
    setClosingRowId(null)
  }

  const handleToggleExpandedRow = (rowKey) => {
    if (expandedRowId === rowKey) {
      setExpandedRowId(null)
      setClosingRowId(rowKey)

      window.setTimeout(() => {
        setClosingRowId((prev) => (prev === rowKey ? null : prev))
      }, EXPAND_ANIMATION_MS)

      return
    }

    setClosingRowId(null)
    setExpandedRowId(rowKey)
    setDetailTab('table')
  }

  const normalizeOneRow = (item, index) => {
    const src = item?._source || item?.raw || item || {}

    const eventType =
      toDisplayText(getNested(src, 'suricata.eve.event_type'), '') ||
      toDisplayText(getNested(src, 'event.type'), '') ||
      toDisplayText(src.event_type, '') ||
      '-'

    const action =
      toDisplayText(item.action, '') ||
      toDisplayText(src.action, '') ||
      toDisplayText(getNested(src, 'network.direction'), '') ||
      eventType ||
      '-'

    const rule =
      toDisplayText(item.rule, '') ||
      toDisplayText(src.rule, '') ||
      toDisplayText(getNested(src, 'suricata.eve.alert.signature'), '') ||
      toDisplayText(getNested(src, 'rule.name'), '') ||
      eventType ||
      '-'

    const category =
      toDisplayText(item.category, '') ||
      toDisplayText(src.category, '') ||
      toDisplayText(getNested(src, 'suricata.eve.alert.category'), '') ||
      toDisplayText(getNested(src, 'event.category'), '') ||
      toDisplayText(getNested(src, 'event.dataset'), '') ||
      '-'

    const severity =
      toDisplayText(item.severity, '') ||
      toDisplayText(src.severity, '') ||
      toDisplayText(getNested(src, 'suricata.eve.alert.severity'), '') ||
      toDisplayText(getNested(src, 'event.severity'), '') ||
      '-'

    const host =
      toDisplayText(item.host_name, '') ||
      toDisplayText(item.hostname, '') ||
      toDisplayText(getNested(src, 'host.name'), '') ||
      toDisplayText(getNested(src, 'host.hostname'), '') ||
      toDisplayText(getNested(src, 'host.ip'), '') ||
      toDisplayText(src.host, '')

    return {
      id: toDisplayText(
        item.id || item._id || `${src['@timestamp'] || 'log'}-${index}`,
      ),
      elastic_id: item._id || item.id || '-',
      elastic_index: item._index || '-',
      elastic_score: item._score ?? '-',
      elastic_type: item._type || '_doc',
      timestamp: toDisplayText(item.timestamp || src['@timestamp']),
      action,
      interface:
        toDisplayText(item.interface, '') ||
        toDisplayText(src.interface, '') ||
        toDisplayText(getNested(src, 'suricata.eve.in_iface'), '') ||
        '-',
      protocol:
        toDisplayText(item.protocol, '') ||
        toDisplayText(src.protocol, '') ||
        toDisplayText(getNested(src, 'network.transport'), '') ||
        toDisplayText(src.proto, '') ||
        '-',
      source_ip:
        toDisplayText(item.source_ip, '') ||
        toDisplayText(item.src_ip, '') ||
        toDisplayText(src.source_ip, '') ||
        toDisplayText(src.src_ip, '') ||
        toDisplayText(getNested(src, 'source.ip'), '') ||
        '-',
      source_port:
        toDisplayText(item.source_port, '') ||
        toDisplayText(item.src_port, '') ||
        toDisplayText(src.source_port, '') ||
        toDisplayText(src.src_port, '') ||
        toDisplayText(getNested(src, 'source.port'), '') ||
        '-',
      destination_ip:
        toDisplayText(item.destination_ip, '') ||
        toDisplayText(item.dest_ip, '') ||
        toDisplayText(src.destination_ip, '') ||
        toDisplayText(src.dest_ip, '') ||
        toDisplayText(getNested(src, 'destination.ip'), '') ||
        '-',
      destination_port:
        toDisplayText(item.destination_port, '') ||
        toDisplayText(item.dest_port, '') ||
        toDisplayText(src.destination_port, '') ||
        toDisplayText(src.dest_port, '') ||
        toDisplayText(getNested(src, 'destination.port'), '') ||
        '-',
      rule,
      severity,
      category,
      host: host || '-',
      event_type: eventType,
      raw: src,
    }
  }

  const normalizeRows = (payload) => {
    let list = []

    if (Array.isArray(payload?.rows)) list = payload.rows
    else if (Array.isArray(payload?.data?.rows)) list = payload.data.rows
    else if (Array.isArray(payload?.hits?.hits)) list = payload.hits.hits
    else if (Array.isArray(payload?.data?.hits?.hits))
      list = payload.data.hits.hits
    else if (Array.isArray(payload)) list = payload

    return list.map((item, index) => normalizeOneRow(item, index))
  }

  const parseWhereConditions = (sql) => {
    const match = sql.match(/\bwhere\b(.+?)(\border\s+by\b|\blimit\b|$)/i)

    if (!match) return []

    const whereText = match[1].trim()

    return whereText
      .split(/\s+and\s+/i)
      .map((condition) => condition.trim())
      .map((condition) => {
        const likeMatch = condition.match(
          /^([a-zA-Z0-9_.]+)\s+like\s+['"](.+)['"]$/i,
        )

        if (likeMatch) {
          return {
            field: likeMatch[1],
            operator: 'like',
            value: likeMatch[2].replaceAll('%', '').toLowerCase(),
          }
        }

        const equalMatch = condition.match(
          /^([a-zA-Z0-9_.]+)\s*=\s*['"]?(.+?)['"]?$/i,
        )

        if (equalMatch) {
          return {
            field: equalMatch[1],
            operator: '=',
            value: equalMatch[2],
          }
        }

        return null
      })
      .filter(Boolean)
  }

  const parseLimit = (sql) => {
    const match = sql.match(/\blimit\s+(\d+)/i)

    if (!match) return 100

    return Number(match[1]) || 100
  }

  const applySqlLikeQuery = (sourceRows, sql) => {
    const conditions = parseWhereConditions(sql)
    const limit = parseLimit(sql)

    let nextRows = [...sourceRows]

    conditions.forEach((condition) => {
      nextRows = nextRows.filter((row) => {
        const value = toDisplayText(row[condition.field], '').toLowerCase()

        if (condition.operator === 'like') {
          return value.includes(condition.value)
        }

        if (condition.operator === '=') {
          return value === String(condition.value).toLowerCase()
        }

        return true
      })
    })

    if (/\border\s+by\s+timestamp\s+desc/i.test(sql)) {
      nextRows.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    }

    if (/\border\s+by\s+timestamp\s+asc/i.test(sql)) {
      nextRows.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    }

    return nextRows.slice(0, limit)
  }

  const handleSearch = async (e) => {
    e.preventDefault()

    if (!selectedFirewall) {
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    try {
      setLoading(true)
      setError('')
      closeExpandedImmediately()

      const data = await fetchEventLogs(DEFAULT_FILTERS)
      const normalized = normalizeRows(data)
      const result = applySqlLikeQuery(normalized, query)

      setRows(normalized)
      setResultRows(result)
    } catch (err) {
      setRows([])
      setResultRows([])
      setError(err.message || 'SQL 로그 검색에 실패했습니다.')
    } finally {
      setLoading(false)
    }
  }

  const sampleQueries = useMemo(
    () => [
      "SELECT * FROM logs WHERE action = 'flow' LIMIT 50",
      "SELECT * FROM logs WHERE protocol = 'UDP' LIMIT 50",
      "SELECT * FROM logs WHERE source_ip = '192.168.0.2' LIMIT 50",
      "SELECT * FROM logs WHERE category LIKE '%suricata%' LIMIT 50",
      'SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100',
    ],
    [],
  )

  return (
    <div className="event-logs-page">
      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">SQL Search</p>
            <h2>SQL 로그 검색</h2>
            <span>현재 대상: {selectedName}</span>
          </div>

          <div className={`event-status-chip ${loading ? 'loading' : 'ready'}`}>
            <i />
            {loading ? '검색 중' : '대기 중'}
          </div>
        </div>

        <form onSubmit={handleSearch}>
          <div className="sql-query-box">
            <label htmlFor="sqlQuery">SQL Query</label>
            <textarea
              id="sqlQuery"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="SELECT * FROM logs WHERE source_ip = '192.168.0.2' LIMIT 50"
            />
          </div>

          <div className="event-toolbar">
            <button type="submit" className="event-primary-btn" disabled={loading}>
              {loading ? '검색 중...' : '검색'}
            </button>
          </div>
        </form>

        <div className="sql-sample-box">
          <h3>예시 쿼리</h3>

          <div className="sql-sample-list">
            {sampleQueries.map((item) => (
              <button
                key={item}
                type="button"
                className="sql-sample-btn"
                onClick={() => {
                  setQuery(item)
                  closeExpandedImmediately()
                }}
              >
                {item}
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Search Result</p>
            <h2>검색 결과</h2>
            <span>
              검색 대상 {rows.length}건 / 결과 {resultRows.length}건
            </span>
          </div>
        </div>

        {error ? <div className="event-error">{error}</div> : null}

        <div className="event-table-outer">
          <div className="event-table-inner">
            <table className="event-table event-log-expand-table sql-log-table">
              <colgroup>
                <col className="col-expand" />
                <col className="col-time" />
                <col className="col-action" />
                <col className="col-interface" />
                <col className="col-protocol" />
                <col className="col-ip" />
                <col className="col-port" />
                <col className="col-ip" />
                <col className="col-port" />
                <col className="col-rule" />
                <col className="col-category" />
                <col className="col-host" />
              </colgroup>

              <thead>
                <tr>
                  <th className="event-expand-th"></th>
                  <th>시간</th>
                  <th>Action</th>
                  <th>인터페이스</th>
                  <th>프로토콜</th>
                  <th>출발지 IP</th>
                  <th>출발지 Port</th>
                  <th>목적지 IP</th>
                  <th>목적지 Port</th>
                  <th>Rule</th>
                  <th>카테고리</th>
                  <th>Host</th>
                </tr>
              </thead>

              <tbody>
                {resultRows.length === 0 ? (
                  <tr>
                    <td colSpan="12" className="event-empty">
                      검색 결과가 없습니다.
                    </td>
                  </tr>
                ) : (
                  resultRows.map((row, index) => {
                    const rowKey = row.id || `${row.timestamp}-${index}`
                    const expanded = expandedRowId === rowKey
                    const closing = closingRowId === rowKey
                    const showDetail = expanded || closing

                    return (
                      <Fragment key={rowKey}>
                        <tr
                          className={`event-clickable-row ${
                            expanded ? 'expanded' : ''
                          }`}
                          onClick={() => handleToggleExpandedRow(rowKey)}
                        >
                          <td className="event-expand-cell">
                            <button
                              type="button"
                              className={`event-row-arrow ${
                                expanded ? 'open' : ''
                              }`}
                              onClick={(e) => {
                                e.stopPropagation()
                                handleToggleExpandedRow(rowKey)
                              }}
                              aria-label={
                                expanded ? '로그 상세 접기' : '로그 상세 펼치기'
                              }
                            >
                              <svg viewBox="0 0 20 20" aria-hidden="true">
                                <path d="M7.2 4.8 12.4 10l-5.2 5.2 1.4 1.4L15.2 10 8.6 3.4 7.2 4.8z" />
                              </svg>
                            </button>
                          </td>

                          <td className="event-cell-time">
                            {formatDateTime(row.timestamp)}
                          </td>
                          <td>
                            <span className="event-action-badge">
                              {toDisplayText(row.action)}
                            </span>
                          </td>
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.interface)}
                          </td>
                          <td className="event-cell-center">
                            {toDisplayText(row.protocol)}
                          </td>
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.source_ip)}
                          </td>
                          <td className="event-cell-center">
                            {toDisplayText(row.source_port)}
                          </td>
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.destination_ip)}
                          </td>
                          <td className="event-cell-center">
                            {toDisplayText(row.destination_port)}
                          </td>
                          <td className="event-cell-rule">
                            {toDisplayText(row.rule)}
                          </td>
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.category)}
                          </td>
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.host)}
                          </td>
                        </tr>

                        {showDetail ? (
                          <tr
                            className={`event-expanded-row ${
                              closing ? 'closing' : 'opening'
                            }`}
                          >
                            <td colSpan="12">
                              <EventLogDetail
                                row={row}
                                activeTab={detailTab}
                                setActiveTab={setDetailTab}
                              />
                            </td>
                          </tr>
                        ) : null}
                      </Fragment>
                    )
                  })
                )}
              </tbody>
            </table>

            <div className="event-table-footer">
              <div className="event-page-info">
                현재 프론트엔드에서 SQL 유사 문법으로 필터링합니다.
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default FirewallLogSqlSearchPage
