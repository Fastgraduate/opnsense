import { useEffect, useMemo, useState } from 'react'

const EMPTY_FILTERS = {
  size: 50,
  minutes: 60,
  action: '',
  interface: '',
  query: '',
}

const getNested = (obj, path, fallback = '') => {
  if (!obj || !path) return fallback

  const value = path.split('.').reduce((acc, key) => {
    if (acc && typeof acc === 'object' && key in acc) {
      return acc[key]
    }
    return undefined
  }, obj)

  return value ?? fallback
}

const formatDateTime = (value) => {
  if (!value) return '-'

  try {
    return new Date(value).toLocaleString('ko-KR', {
      hour12: false,
    })
  } catch {
    return value
  }
}

function FirewallEventLogsPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const selectedName = selectedFirewall?.name || '없음'

  const handleChange = (e) => {
    const { name, value } = e.target
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

    if (Array.isArray(payload?.rows)) {
      list = payload.rows
    } else if (Array.isArray(payload?.data?.rows)) {
      list = payload.data.rows
    } else if (Array.isArray(payload?.hits?.hits)) {
      list = payload.hits.hits
    } else if (Array.isArray(payload?.data?.hits?.hits)) {
      list = payload.data.hits.hits
    } else if (Array.isArray(payload)) {
      list = payload
    }

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
      const normalized = normalizeRows(data)

      console.log('[FirewallEventLogsPage] raw response:', data)
      console.log('[FirewallEventLogsPage] normalized rows:', normalized)

      setRows(normalized)
    } catch (err) {
      setRows([])
      setError(err.message || '이벤트 로그를 불러오지 못했습니다.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!selectedFirewall) {
      setRows([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    loadLogs()
  }, [selectedFirewall])

  const handleSubmit = async (e) => {
    e.preventDefault()
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
  }, [rows, filters.action, filters.interface, filters.query])

  return (
    <div className="page">
      <section className="card">
        <div className="card-header-row">
          <h3>방화벽 이벤트 로그</h3>
          <span className="rule-count">현재 대상: {selectedName}</span>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            <div>
              <label>최근 범위(분)</label>
              <select
                name="minutes"
                value={filters.minutes}
                onChange={handleChange}
              >
                <option value={5}>5분</option>
                <option value={15}>15분</option>
                <option value={60}>1시간</option>
                <option value={180}>3시간</option>
                <option value={720}>12시간</option>
                <option value={1440}>24시간</option>
              </select>
            </div>

            <div>
              <label>개수</label>
              <select name="size" value={filters.size} onChange={handleChange}>
                <option value={20}>20개</option>
                <option value={50}>50개</option>
                <option value={100}>100개</option>
                <option value={200}>200개</option>
              </select>
            </div>

            <div>
              <label>Action</label>
              <select
                name="action"
                value={filters.action}
                onChange={handleChange}
              >
                {actionOptions.map((item) => (
                  <option key={item || 'all'} value={item}>
                    {item || '전체'}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label>Interface</label>
              <select
                name="interface"
                value={filters.interface}
                onChange={handleChange}
              >
                {interfaceOptions.map((item) => (
                  <option key={item || 'all'} value={item}>
                    {item || '전체'}
                  </option>
                ))}
              </select>
            </div>

            <div style={{ gridColumn: '1 / -1' }}>
              <label>검색</label>
              <input
                name="query"
                value={filters.query}
                onChange={handleChange}
                placeholder="IP, rule, message, protocol 등"
              />
            </div>
          </div>

          <div className="form-actions">
            <button type="submit" disabled={loading || !selectedFirewall}>
              {loading ? '불러오는 중...' : '로그 조회'}
            </button>
          </div>
        </form>
      </section>

      <section className="card" style={{ marginTop: '16px' }}>
        <div className="card-header-row">
          <h3>이벤트 목록</h3>
          <span className="rule-count">총 {filteredRows.length}건</span>
        </div>

        {error ? <div className="error-text">{error}</div> : null}

        <div className="table-wrap">
          <table>
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
              {filteredRows.length === 0 ? (
                <tr>
                  <td colSpan="12">
                    {loading
                      ? '로그를 불러오는 중입니다.'
                      : '표시할 로그가 없습니다.'}
                  </td>
                </tr>
              ) : (
                filteredRows.map((row, index) => (
                  <tr key={row.id || `${row.timestamp}-${index}`}>
                    <td>{formatDateTime(row.timestamp)}</td>
                    <td>{row.action || '-'}</td>
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
        </div>
      </section>
    </div>
  )
}

export default FirewallEventLogsPage
