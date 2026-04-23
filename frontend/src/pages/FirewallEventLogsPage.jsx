import { useEffect, useState } from 'react'

function FirewallEventLogsPage({ selectedFirewall, fetchEventLogs }) {
  const [filters, setFilters] = useState({ size: 50, minutes: 60, action: '', interface: '', query: '' })
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    if (!selectedFirewall) return
    setLoading(true)
    setError('')
    try {
      const data = await fetchEventLogs(filters)
      setRows(Array.isArray(data?.rows) ? data.rows : [])
    } catch (e) {
      setError(e.message || '이벤트 로그 조회 실패')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [selectedFirewall])

  const handleChange = (e) => {
    const { name, value } = e.target
    setFilters((prev) => ({ ...prev, [name]: value }))
  }

  return (
    <div className="page">
      <div className="card">
        <div className="section-header">
          <h3>방화벽 이벤트 로그</h3>
          <div className="rule-count">대상: {selectedFirewall?.name || '-'}</div>
        </div>
        <div className="form-grid">
          <div><label>최근(분)</label><input name="minutes" value={filters.minutes} onChange={handleChange} /></div>
          <div><label>최대 건수</label><input name="size" value={filters.size} onChange={handleChange} /></div>
          <div><label>Action</label><input name="action" value={filters.action} onChange={handleChange} placeholder="allowed / blocked" /></div>
          <div><label>Interface</label><input name="interface" value={filters.interface} onChange={handleChange} placeholder="WAN / LAN" /></div>
          <div style={{ gridColumn: '1 / -1' }}><label>검색어</label><input name="query" value={filters.query} onChange={handleChange} placeholder="IP, rule, protocol" /></div>
        </div>
        <div className="form-actions"><button onClick={load} disabled={!selectedFirewall || loading}>{loading ? '조회 중...' : '로그 조회'}</button></div>
        {error ? <p className="error-text">{error}</p> : null}
        <div className="table-wrap" style={{ marginTop: '16px' }}>
          <table className="dashboard-table">
            <thead>
              <tr>
                <th>시간</th><th>Action</th><th>Interface</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Rule</th><th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 ? <tr><td colSpan="8">로그가 없습니다.</td></tr> : rows.map((row, idx) => (
                <tr key={`${row.timestamp}-${idx}`}>
                  <td>{row.timestamp}</td>
                  <td>{row.action}</td>
                  <td>{row.interface}</td>
                  <td>{row.protocol}</td>
                  <td>{row.source_ip}:{row.source_port}</td>
                  <td>{row.destination_ip}:{row.destination_port}</td>
                  <td>{row.rule}</td>
                  <td>{row.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default FirewallEventLogsPage
