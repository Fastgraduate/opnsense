import { Fragment, useEffect, useMemo, useState } from 'react'

const DEFAULT_FILTERS = {
  size: 500,
  minutes: 0,
  action: '',
  interface: '',
  query: '',
}

const INDEX_OPTIONS = [
  { value: 'date', label: '날짜별' },
  { value: 'hour', label: '시간별' },
  { value: 'interface', label: '인터페이스별' },
  { value: 'action', label: 'Action별' },
  { value: 'protocol', label: '프로토콜별' },
  { value: 'source_ip', label: '출발지 IP별' },
  { value: 'destination_ip', label: '목적지 IP별' },
  { value: 'severity', label: '심각도별' },
  { value: 'category', label: '카테고리별' },
  { value: 'host', label: 'Host별' },
]

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

const getDateKey = (value) => {
  if (!value || value === '-') return '-'

  try {
    return new Date(value).toISOString().slice(0, 10)
  } catch {
    return '-'
  }
}

const getHourKey = (value) => {
  if (!value || value === '-') return '-'

  try {
    const date = new Date(value)
    const ymd = date.toISOString().slice(0, 10)
    const hour = String(date.getHours()).padStart(2, '0')
    return `${ymd} ${hour}:00`
  } catch {
    return '-'
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

function FirewallLogIndexPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS)
  const [indexField, setIndexField] = useState('date')
  const [selectedIndex, setSelectedIndex] = useState('')
  const [rows, setRows] = useState([])
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

  const handleChange = (e) => {
    const { name, value } = e.target

    setSelectedIndex('')
    closeExpandedImmediately()

    setFilters((prev) => ({
      ...prev,
      [name]: name === 'size' || name === 'minutes' ? Number(value) : value,
    }))
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

  const loadLogs = async () => {
    if (!selectedFirewall) {
      setRows([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    try {
      setLoading(true)
      setError('')

      const data = await fetchEventLogs(filters)
      setRows(normalizeRows(data))
    } catch (err) {
      setRows([])
      setError(err.message || '로그를 불러오지 못했습니다.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadLogs()
  }, [selectedFirewall])

  const searchableText = (row) => {
    return [
      row.timestamp,
      row.action,
      row.interface,
      row.protocol,
      row.source_ip,
      row.source_port,
      row.destination_ip,
      row.destination_port,
      row.rule,
      row.severity,
      row.category,
      row.host,
      row.event_type,
    ]
      .map((value) => toDisplayText(value, ''))
      .join(' ')
      .toLowerCase()
  }

  const filteredRows = useMemo(() => {
    const keyword = filters.query.trim().toLowerCase()

    return rows.filter((row) => {
      if (
        filters.action &&
        row.action !== filters.action &&
        row.event_type !== filters.action
      ) {
        return false
      }

      if (filters.interface && row.interface !== filters.interface) {
        return false
      }

      if (!keyword) return true

      return searchableText(row).includes(keyword)
    })
  }, [rows, filters])

  const getIndexKey = (row) => {
    if (indexField === 'date') return getDateKey(row.timestamp)
    if (indexField === 'hour') return getHourKey(row.timestamp)

    return toDisplayText(row[indexField])
  }

  const indexedGroups = useMemo(() => {
    const map = new Map()

    filteredRows.forEach((row) => {
      const key = getIndexKey(row)

      if (!map.has(key)) {
        map.set(key, {
          key,
          count: 0,
          rows: [],
        })
      }

      const group = map.get(key)
      group.count += 1
      group.rows.push(row)
    })

    return Array.from(map.values()).sort((a, b) => b.count - a.count)
  }, [filteredRows, indexField])

  const displayedRows = useMemo(() => {
    if (!selectedIndex) return filteredRows

    const group = indexedGroups.find((item) => item.key === selectedIndex)

    return group?.rows || []
  }, [filteredRows, indexedGroups, selectedIndex])

  const interfaceOptions = useMemo(() => {
    const values = Array.from(
      new Set(
        rows
          .map((row) => toDisplayText(row.interface))
          .filter((x) => x && x !== '-'),
      ),
    )

    return ['', ...values]
  }, [rows])

  const actionOptions = useMemo(() => {
    const values = Array.from(
      new Set(
        rows
          .map((row) => toDisplayText(row.action))
          .filter((x) => x && x !== '-'),
      ),
    )

    return ['', ...values]
  }, [rows])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSelectedIndex('')
    closeExpandedImmediately()
    await loadLogs()
  }

  const renderSelect = ({ label, name, value, onChange, children }) => (
    <div className="event-input-field">
      <label htmlFor={name}>{label}</label>
      <div className="event-select-wrap">
        <select id={name} name={name} value={value} onChange={onChange}>
          {children}
        </select>

        <span className="event-select-icon">
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path
              fillRule="evenodd"
              d="M10 3a1 1 0 01.707.293l3 3a1 1 0 01-1.414 1.414L10 5.414 7.707 7.707a1 1 0 01-1.414-1.414l3-3A1 1 0 0110 3zm-3.707 9.293a1 1 0 011.414 0L10 14.586l2.293-2.293a1 1 0 011.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z"
              clipRule="evenodd"
            />
          </svg>
        </span>
      </div>
    </div>
  )

  return (
    <div className="event-logs-page">
      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Log Indexing</p>
            <h2>방화벽 로그 인덱싱</h2>
            <span>현재 대상: {selectedName}</span>
          </div>

          <div className={`event-status-chip ${loading ? 'loading' : 'ready'}`}>
            <i />
            {loading ? '인덱싱 중' : '대기 중'}
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="event-filter-grid">
            {renderSelect({
              label: '인덱싱 기준',
              name: 'indexField',
              value: indexField,
              onChange: (e) => {
                setSelectedIndex('')
                closeExpandedImmediately()
                setIndexField(e.target.value)
              },
              children: INDEX_OPTIONS.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              )),
            })}

            {renderSelect({
              label: '개수',
              name: 'size',
              value: filters.size,
              onChange: handleChange,
              children: (
                <>
                  <option value={100}>100개</option>
                  <option value={200}>200개</option>
                  <option value={500}>500개</option>
                  <option value={1000}>1000개</option>
                </>
              ),
            })}

            {renderSelect({
              label: 'Action 필터',
              name: 'action',
              value: filters.action,
              onChange: handleChange,
              children: actionOptions.map((item) => (
                <option key={item || 'all'} value={item}>
                  {item || '전체'}
                </option>
              )),
            })}

            {renderSelect({
              label: 'Interface 필터',
              name: 'interface',
              value: filters.interface,
              onChange: handleChange,
              children: interfaceOptions.map((item) => (
                <option key={item || 'all'} value={item}>
                  {item || '전체'}
                </option>
              )),
            })}

            <div className="event-search-field">
              <div className="event-input-field">
                <label htmlFor="query">검색 필터</label>
                <input
                  id="query"
                  name="query"
                  value={filters.query}
                  onChange={handleChange}
                  placeholder="IP, rule, host, category 등"
                />
              </div>
            </div>
          </div>

          <div className="event-toolbar">
            <button type="submit" className="event-primary-btn" disabled={loading}>
              {loading ? '불러오는 중...' : '인덱싱 적용'}
            </button>

            <button
              type="button"
              className="event-secondary-btn"
              onClick={() => {
                setFilters(DEFAULT_FILTERS)
                setIndexField('date')
                setSelectedIndex('')
                closeExpandedImmediately()
              }}
            >
              초기화
            </button>
          </div>
        </form>
      </section>

      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Index Groups</p>
            <h2>인덱싱 결과</h2>
            <span>
              전체 {filteredRows.length}건 / 그룹 {indexedGroups.length}개
            </span>
          </div>

          <button
            type="button"
            className="event-secondary-btn"
            disabled={!selectedIndex}
            onClick={() => {
              setSelectedIndex('')
              closeExpandedImmediately()
            }}
          >
            전체 보기
          </button>
        </div>

        {error ? <div className="event-error">{error}</div> : null}

        <div className="log-index-grid">
          {indexedGroups.length === 0 ? (
            <div className="event-chart-empty">인덱싱할 로그가 없습니다.</div>
          ) : (
            indexedGroups.map((group) => (
              <button
                type="button"
                key={toDisplayText(group.key)}
                className={`log-index-card ${
                  selectedIndex === group.key ? 'active' : ''
                }`}
                onClick={() => {
                  setSelectedIndex(group.key)
                  closeExpandedImmediately()
                }}
              >
                <span>{toDisplayText(group.key)}</span>
                <strong>{group.count.toLocaleString()}건</strong>
              </button>
            ))
          )}
        </div>
      </section>

      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Indexed Logs</p>
            <h2>인덱싱 로그 목록</h2>
            <span>
              표시 중: {displayedRows.length}건
              {selectedIndex ? ` / 선택 인덱스: ${toDisplayText(selectedIndex)}` : ''}
            </span>
          </div>
        </div>

        <div className="event-table-outer">
          <div className="event-table-inner">
            <table className="event-table event-log-expand-table index-log-table">
              <colgroup>
                <col className="col-expand" />
                <col className="col-time" />
                <col className="col-action" />
                <col className="col-interface" />
                <col className="col-protocol" />
                <col className="col-ip" />
                <col className="col-ip" />
                <col className="col-rule" />
                <col className="col-severity" />
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
                  <th>목적지 IP</th>
                  <th>Rule</th>
                  <th>심각도</th>
                  <th>카테고리</th>
                  <th>Host</th>
                </tr>
              </thead>

              <tbody>
                {displayedRows.length === 0 ? (
                  <tr>
                    <td colSpan="11" className="event-empty">
                      표시할 로그가 없습니다.
                    </td>
                  </tr>
                ) : (
                  displayedRows.slice(0, 100).map((row, index) => {
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
                          <td className="event-cell-ellipsis">
                            {toDisplayText(row.destination_ip)}
                          </td>
                          <td className="event-cell-rule">
                            {toDisplayText(row.rule)}
                          </td>
                          <td className="event-cell-center">
                            {toDisplayText(row.severity)}
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
                            <td colSpan="11">
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
                화면 성능을 위해 최대 100건만 미리보기 표시
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default FirewallLogIndexPage
