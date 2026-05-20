import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Chart,
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from 'chart.js'

Chart.register(
  BarController,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
)

const EMPTY_FILTERS = {
  size: 200,
  minutes: 60,
  action: '',
  interface: '',
  query: '',
}

const TIME_OPTIONS = [
  { label: '전체 시간', value: 0 },
  { label: '5분', value: 5 },
  { label: '15분', value: 15 },
  { label: '1시간', value: 60 },
  { label: '3시간', value: 180 },
  { label: '12시간', value: 720 },
  { label: '24시간', value: 1440 },
]

const PAGE_SIZE = 30
const REFRESH_INTERVAL_MS = 10000

const getNested = (obj, path, fallback = '') => {
  if (!obj || !path) return fallback

  const value = path.split('.').reduce((acc, key) => {
    if (acc && typeof acc === 'object' && key in acc) return acc[key]
    return undefined
  }, obj)

  return value ?? fallback
}

const formatDateTime = (value) => {
  if (!value) return '-'

  try {
    return new Date(value).toLocaleString('ko-KR', { hour12: false })
  } catch {
    return value
  }
}

const formatTimeOnly = (value) => {
  if (!value) return '-'

  try {
    return new Date(value).toLocaleTimeString('ko-KR', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return value
  }
}

const getBucketSizeMs = (rows) => {
  if (rows.length <= 1) return 60 * 1000

  const times = rows
    .map((row) => new Date(row.timestamp).getTime())
    .filter((time) => Number.isFinite(time))

  if (times.length <= 1) return 60 * 1000

  const range = Math.max(...times) - Math.min(...times)

  if (range <= 5 * 60 * 1000) return 5 * 1000
  if (range <= 15 * 60 * 1000) return 15 * 1000
  if (range <= 60 * 60 * 1000) return 60 * 1000
  if (range <= 3 * 60 * 60 * 1000) return 5 * 60 * 1000
  if (range <= 12 * 60 * 60 * 1000) return 15 * 60 * 1000
  if (range <= 24 * 60 * 60 * 1000) return 30 * 60 * 1000

  return 60 * 60 * 1000
}

function EventLogBarChart({ buckets, selectedBucket, onSelectBucket }) {
  const canvasRef = useRef(null)
  const chartRef = useRef(null)

  const labels = useMemo(
    () =>
      buckets.map((bucket) => {
        const start = formatTimeOnly(bucket.start)
        const end = formatTimeOnly(bucket.end)
        return `${start}~${end}`
      }),
    [buckets],
  )

  const values = useMemo(() => buckets.map((bucket) => bucket.count), [buckets])

  const colors = useMemo(
    () =>
      buckets.map((bucket) => {
        const active =
          selectedBucket &&
          selectedBucket.start === bucket.start &&
          selectedBucket.end === bucket.end

        return active ? '#111827' : '#8470ff'
      }),
    [buckets, selectedBucket],
  )

  useEffect(() => {
    if (!canvasRef.current || chartRef.current) return

    chartRef.current = new Chart(canvasRef.current, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          {
            label: '로그 수',
            data: values,
            backgroundColor: colors,
            borderRadius: 8,
            barPercentage: 0.75,
            categoryPercentage: 0.8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 650,
          easing: 'easeOutQuart',
        },
        animations: {
          numbers: {
            type: 'number',
            properties: ['y', 'base'],
            duration: 650,
            easing: 'easeOutQuart',
          },
        },
        onClick: (_, elements) => {
          if (!elements.length) return

          const index = elements[0].index
          const bucket = buckets[index]

          if (bucket) {
            onSelectBucket(bucket)
          }
        },
        interaction: {
          intersect: false,
          mode: 'index',
        },
        plugins: {
          legend: {
            display: false,
          },
          tooltip: {
            backgroundColor: '#111827',
            titleColor: '#ffffff',
            bodyColor: '#e5e7eb',
            padding: 10,
            callbacks: {
              title: (items) => {
                const index = items[0]?.dataIndex
                const bucket = buckets[index]
                if (!bucket) return '-'

                return `${formatTimeOnly(bucket.start)} ~ ${formatTimeOnly(
                  bucket.end,
                )}`
              },
              label: (context) => `로그 ${context.raw}건`,
            },
          },
        },
        scales: {
          x: {
            grid: {
              display: false,
            },
            ticks: {
              color: '#94a3b8',
              maxRotation: 0,
              autoSkip: true,
            },
          },
          y: {
            beginAtZero: true,
            grid: {
              color: '#f1f5f9',
            },
            ticks: {
              color: '#94a3b8',
              precision: 0,
            },
          },
        },
      },
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

    chart.options.onClick = (_, elements) => {
      if (!elements.length) return

      const index = elements[0].index
      const bucket = buckets[index]

      if (bucket) {
        onSelectBucket(bucket)
      }
    }

    chart.options.plugins.tooltip.callbacks.title = (items) => {
      const index = items[0]?.dataIndex
      const bucket = buckets[index]
      if (!bucket) return '-'

      return `${formatTimeOnly(bucket.start)} ~ ${formatTimeOnly(bucket.end)}`
    }

    chart.update()
  }, [labels, values, colors, buckets, onSelectBucket])

  return (
    <div className="event-chart-canvas">
      <canvas ref={canvasRef} />
    </div>
  )
}

function FirewallEventLogsPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [rows, setRows] = useState([])
  const [selectedBucket, setSelectedBucket] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const selectedName = selectedFirewall?.name || '없음'

  const handleChange = (e) => {
    const { name, value } = e.target

    setSelectedBucket(null)
    setCurrentPage(1)

    setFilters((prev) => ({
      ...prev,
      [name]: name === 'size' || name === 'minutes' ? Number(value) : value,
    }))
  }

  const normalizeOneRow = (item, index) => {
    const src = item?._source || item?.raw || item || {}

    const eventType =
      getNested(src, 'suricata.eve.event_type') ||
      getNested(src, 'event.type') ||
      src.event_type ||
      '-'

    const action =
      item.action ||
      src.action ||
      getNested(src, 'network.direction') ||
      eventType ||
      '-'

    const rule =
      item.rule ||
      src.rule ||
      getNested(src, 'suricata.eve.alert.signature') ||
      getNested(src, 'rule.name') ||
      eventType ||
      '-'

    const category =
      item.category ||
      src.category ||
      getNested(src, 'suricata.eve.alert.category') ||
      getNested(src, 'event.category') ||
      getNested(src, 'event.dataset') ||
      '-'

    const severity =
      item.severity ??
      src.severity ??
      getNested(src, 'suricata.eve.alert.severity') ??
      getNested(src, 'event.severity') ??
      '-'

    return {
      id: item.id || item._id || `${src['@timestamp'] || 'log'}-${index}`,
      timestamp: item.timestamp || src['@timestamp'] || '-',
      action,
      interface:
        item.interface ||
        src.interface ||
        getNested(src, 'suricata.eve.in_iface') ||
        '-',
      protocol:
        item.protocol ||
        src.protocol ||
        getNested(src, 'network.transport') ||
        src.proto ||
        '-',
      source_ip:
        item.source_ip ||
        item.src_ip ||
        src.source_ip ||
        src.src_ip ||
        getNested(src, 'source.ip') ||
        '-',
      source_port:
        item.source_port ??
        item.src_port ??
        src.source_port ??
        src.src_port ??
        getNested(src, 'source.port') ??
        '-',
      destination_ip:
        item.destination_ip ||
        item.dest_ip ||
        src.destination_ip ||
        src.dest_ip ||
        getNested(src, 'destination.ip') ||
        '-',
      destination_port:
        item.destination_port ??
        item.dest_port ??
        src.destination_port ??
        src.dest_port ??
        getNested(src, 'destination.port') ??
        '-',
      rule,
      severity,
      category,
      host:
        item.host ||
        src.host ||
        getNested(src, 'host.name') ||
        getNested(src, 'host.hostname') ||
        '-',
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

  const loadLogs = async ({ silent = false } = {}) => {
    if (!selectedFirewall) {
      setRows([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    try {
      if (!silent) setLoading(true)

      setError('')

      const data = await fetchEventLogs(filters)
      const normalized = normalizeRows(data)

      setRows(normalized)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setRows([])
      setError(err.message || '이벤트 로그를 불러오지 못했습니다.')
    } finally {
      if (!silent) setLoading(false)
    }
  }

  useEffect(() => {
    if (!selectedFirewall) {
      setRows([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    setSelectedBucket(null)
    setCurrentPage(1)
    loadLogs()
  }, [selectedFirewall])

  useEffect(() => {
    if (!selectedFirewall || !autoRefresh) return

    const timer = setInterval(() => {
      loadLogs({ silent: true })
    }, REFRESH_INTERVAL_MS)

    return () => clearInterval(timer)
  }, [selectedFirewall, autoRefresh, filters])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSelectedBucket(null)
    setCurrentPage(1)
    await loadLogs()
  }

  const actionOptions = useMemo(
    () => [
      '',
      'inbound',
      'outbound',
      'allowed',
      'blocked',
      'drop',
      'alert',
      'flow',
      'dns',
      'http',
      'tls',
    ],
    [],
  )

  const interfaceOptions = useMemo(() => {
    const values = Array.from(
      new Set(
        rows
          .map((row) => row.interface)
          .filter(Boolean)
          .filter((x) => x !== '-'),
      ),
    )

    return ['', ...values]
  }, [rows])

  const baseFilteredRows = useMemo(() => {
    const keyword = filters.query.trim().toLowerCase()
    const now = Date.now()
    const minutesMs = filters.minutes * 60 * 1000

    return rows.filter((row) => {
      const rowTime = new Date(row.timestamp).getTime()

      if (
        filters.minutes > 0 &&
        Number.isFinite(rowTime) &&
        rowTime < now - minutesMs
      ) {
        return false
      }

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
        .join(' ')
        .toLowerCase()
        .includes(keyword)
    })
  }, [rows, filters])

  const chartBuckets = useMemo(() => {
    const validRows = baseFilteredRows
      .map((row) => ({
        ...row,
        timeMs: new Date(row.timestamp).getTime(),
      }))
      .filter((row) => Number.isFinite(row.timeMs))

    if (validRows.length === 0) return []

    const bucketSize = getBucketSizeMs(validRows)
    const map = new Map()

    validRows.forEach((row) => {
      const start = Math.floor(row.timeMs / bucketSize) * bucketSize
      const end = start + bucketSize
      const key = String(start)

      if (!map.has(key)) {
        map.set(key, {
          start,
          end,
          count: 0,
        })
      }

      map.get(key).count += 1
    })

    return Array.from(map.values()).sort((a, b) => a.start - b.start)
  }, [baseFilteredRows])

  const displayedRows = useMemo(() => {
    if (!selectedBucket) return baseFilteredRows

    return baseFilteredRows.filter((row) => {
      const time = new Date(row.timestamp).getTime()

      return (
        Number.isFinite(time) &&
        time >= selectedBucket.start &&
        time < selectedBucket.end
      )
    })
  }, [baseFilteredRows, selectedBucket])

  const totalPages = Math.max(1, Math.ceil(displayedRows.length / PAGE_SIZE))

  const pagedRows = useMemo(() => {
    const safePage = Math.min(currentPage, totalPages)
    const start = (safePage - 1) * PAGE_SIZE
    return displayedRows.slice(start, start + PAGE_SIZE)
  }, [displayedRows, currentPage, totalPages])

  useEffect(() => {
    setCurrentPage(1)
  }, [
    selectedBucket,
    filters.action,
    filters.interface,
    filters.query,
    filters.minutes,
  ])

  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(totalPages)
  }, [currentPage, totalPages])

  const selectedBucketLabel = selectedBucket
    ? `${formatDateTime(selectedBucket.start)} ~ ${formatDateTime(
        selectedBucket.end,
      )}`
    : '전체 구간'

  const renderInput = ({ label, name, placeholder }) => (
    <div className="event-input-field">
      <label htmlFor={name}>{label}</label>
      <input
        id={name}
        name={name}
        value={filters[name]}
        onChange={handleChange}
        placeholder={placeholder}
      />
    </div>
  )

  const renderSelect = ({ label, name, children }) => (
    <div className="event-input-field">
      <label htmlFor={name}>{label}</label>

      <div className="event-select-wrap">
        <select
          id={name}
          name={name}
          value={filters[name]}
          onChange={handleChange}
        >
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
            <p className="event-eyebrow">Elastic Event Logs</p>
            <h2>방화벽 이벤트 로그</h2>
            <span>현재 대상: {selectedName}</span>
          </div>

          <div className={`event-status-chip ${loading ? 'loading' : 'ready'}`}>
            <i />
            {loading ? '로그 갱신 중' : '수집 대기 중'}
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="event-filter-grid">
            {renderSelect({
              label: '시간 범위',
              name: 'minutes',
              children: TIME_OPTIONS.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              )),
            })}

            {renderSelect({
              label: '개수',
              name: 'size',
              children: (
                <>
                  <option value={50}>50개</option>
                  <option value={100}>100개</option>
                  <option value={200}>200개</option>
                  <option value={500}>500개</option>
                </>
              ),
            })}

            {renderSelect({
              label: 'Action',
              name: 'action',
              children: actionOptions.map((item) => (
                <option key={item || 'all'} value={item}>
                  {item || '전체'}
                </option>
              )),
            })}

            {renderSelect({
              label: 'Interface',
              name: 'interface',
              children: interfaceOptions.map((item) => (
                <option key={item || 'all'} value={item}>
                  {item || '전체'}
                </option>
              )),
            })}

            <div className="event-search-field">
              {renderInput({
                label: '검색',
                name: 'query',
                placeholder: 'IP, rule, message, protocol 등',
              })}
            </div>
          </div>

          <div className="event-toolbar">
            <button
              type="submit"
              className="event-primary-btn"
              disabled={loading || !selectedFirewall}
            >
              {loading ? '불러오는 중...' : '로그 조회'}
            </button>

            <button
              type="button"
              className={`event-toggle-btn ${autoRefresh ? 'active' : ''}`}
              onClick={() => setAutoRefresh((prev) => !prev)}
            >
              실시간 갱신: {autoRefresh ? 'ON' : 'OFF'}
            </button>

            <span className="event-last-updated">
              마지막 갱신: {lastUpdatedAt ? formatTimeOnly(lastUpdatedAt) : '-'}
            </span>
          </div>
        </form>
      </section>

      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Timeline</p>
            <h2>시간별 로그 분포</h2>
            <span>선택 구간: {selectedBucketLabel}</span>
          </div>

          <button
            type="button"
            className="event-secondary-btn"
            onClick={() => {
              setSelectedBucket(null)
              setCurrentPage(1)
            }}
            disabled={!selectedBucket}
          >
            전체 구간 보기
          </button>
        </div>

        {chartBuckets.length === 0 ? (
          <div className="event-chart-empty">
            표시할 그래프 데이터가 없습니다.
          </div>
        ) : (
          <>
            <EventLogBarChart
              buckets={chartBuckets}
              selectedBucket={selectedBucket}
              onSelectBucket={(bucket) => {
                setSelectedBucket(bucket)
                setCurrentPage(1)
              }}
            />

            <div className="event-chart-caption">
              <span>{formatTimeOnly(chartBuckets[0].start)}</span>
              <span>막대를 클릭하면 해당 시간 구간의 로그만 조회됩니다.</span>
              <span>
                {formatTimeOnly(chartBuckets[chartBuckets.length - 1].end)}
              </span>
            </div>
          </>
        )}
      </section>

      <section className="event-panel">
        <div className="event-panel-header">
          <div>
            <p className="event-eyebrow">Events</p>
            <h2>이벤트 목록</h2>
            <span>
              총 {displayedRows.length}건 / {currentPage} / {totalPages} 페이지
            </span>
          </div>
        </div>

        {error ? <div className="event-error">{error}</div> : null}

        <div className="event-table-outer">
          <div className="event-table-inner">
            <table className="event-table">
              <thead>
                <tr>
                  <th>시간</th>
                  <th>Action</th>
                  <th>인터페이스</th>
                  <th>프로토콜</th>
                  <th>출발지 IP</th>
                  <th>출발지 Port</th>
                  <th>목적지 IP</th>
                  <th>목적지 Port</th>
                  <th>Rule</th>
                  <th>심각도</th>
                  <th>카테고리</th>
                  <th>Host</th>
                </tr>
              </thead>

              <tbody>
                {pagedRows.length === 0 ? (
                  <tr>
                    <td colSpan="12" className="event-empty">
                      {loading
                        ? '로그를 불러오는 중입니다.'
                        : '표시할 로그가 없습니다.'}
                    </td>
                  </tr>
                ) : (
                  pagedRows.map((row, index) => (
                    <tr key={row.id || `${row.timestamp}-${index}`}>
                      <td>{formatDateTime(row.timestamp)}</td>
                      <td>
                        <span className="event-action-badge">
                          {row.action || '-'}
                        </span>
                      </td>
                      <td>{row.interface || '-'}</td>
                      <td>{row.protocol || '-'}</td>
                      <td>{row.source_ip || '-'}</td>
                      <td>{row.source_port ?? '-'}</td>
                      <td>{row.destination_ip || '-'}</td>
                      <td>{row.destination_port ?? '-'}</td>
                      <td>{row.rule || '-'}</td>
                      <td>{row.severity ?? '-'}</td>
                      <td>{row.category || '-'}</td>
                      <td>{row.host || '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>

            <div className="event-table-footer">
              <div className="event-page-info">페이지당 {PAGE_SIZE}개 표시</div>

              <div className="event-pagination">
                <button
                  type="button"
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                >
                  처음
                </button>

                <button
                  type="button"
                  onClick={() =>
                    setCurrentPage((prev) => Math.max(1, prev - 1))
                  }
                  disabled={currentPage === 1}
                >
                  이전
                </button>

                {Array.from({ length: totalPages }, (_, index) => index + 1)
                  .filter((page) => {
                    if (totalPages <= 7) return true
                    if (page === 1 || page === totalPages) return true
                    return Math.abs(page - currentPage) <= 2
                  })
                  .map((page, index, arr) => {
                    const prevPage = arr[index - 1]
                    const showEllipsis = prevPage && page - prevPage > 1

                    return (
                      <span key={page} className="event-page-group">
                        {showEllipsis ? (
                          <span className="event-ellipsis">...</span>
                        ) : null}

                        <button
                          type="button"
                          className={currentPage === page ? 'active' : ''}
                          onClick={() => setCurrentPage(page)}
                          disabled={currentPage === page}
                        >
                          {page}
                        </button>
                      </span>
                    )
                  })}

                <button
                  type="button"
                  onClick={() =>
                    setCurrentPage((prev) => Math.min(totalPages, prev + 1))
                  }
                  disabled={currentPage === totalPages}
                >
                  다음
                </button>

                <button
                  type="button"
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                >
                  마지막
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default FirewallEventLogsPage
