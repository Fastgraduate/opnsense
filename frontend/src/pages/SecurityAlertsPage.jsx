import { useEffect, useMemo, useRef, useState } from 'react'
import '../styles/securityAlerts.css'

const API_BASE = 'http://127.0.0.1:8000'

const LEVEL_LABELS = {
  critical: '매우 높음',
  high: '높음',
  medium: '중간',
  low: '낮음',
}

const STATUS_LABELS = {
  detected: '탐지됨',
  watch: '관찰',
  approval_required: '승인 필요',
  auto_block_candidate: '자동 차단 후보',
  blocked: '차단 완료',
}

const toText = (value, fallback = '-') => {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

function AlertDetailModal({ alert, onClose }) {
  if (!alert) return null

  return (
    <div className="sec-alert-modal-backdrop" onClick={onClose}>
      <div className="sec-alert-modal" onClick={(e) => e.stopPropagation()}>
        <div className="sec-alert-modal-header">
          <div>
            <p className="sec-alert-eyebrow">Attack Detail</p>
            <h3>공격 탐지 상세</h3>
          </div>

          <button type="button" onClick={onClose}>
            닫기
          </button>
        </div>

        <div className="sec-alert-modal-summary">
          <span>위험도: {alert.risk?.score}점</span>
          <span>등급: {LEVEL_LABELS[alert.risk?.level] || alert.risk?.label}</span>
          <span>공격자: {toText(alert.source_ip)}</span>
          <span>대상: {toText(alert.destination_ip)}:{toText(alert.destination_port)}</span>
        </div>

        <div className="sec-alert-reason-box">
          <h4>위험도 산정 이유</h4>
          {alert.risk?.reasons?.length ? (
            <ul>
              {alert.risk.reasons.map((reason, index) => (
                <li key={`${reason}-${index}`}>{reason}</li>
              ))}
            </ul>
          ) : (
            <p>위험도 산정 이유가 없습니다.</p>
          )}
        </div>

        <pre className="sec-alert-modal-pre">
          {JSON.stringify(alert.raw || alert, null, 2)}
        </pre>
      </div>
    </div>
  )
}

function SecurityAlertsPage({ selectedFirewall }) {
  const [alerts, setAlerts] = useState([])
  const [summary, setSummary] = useState(null)
  const [filters, setFilters] = useState({
    minutes: 60,
    size: 200,
    minRisk: 0,
    autoRefresh: true,
    includeAllEvents: false,
    aliasName: 'blocked_attackers',
    forcePrivateBlock: false,
  })
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [loading, setLoading] = useState(false)
  const [blockingId, setBlockingId] = useState('')
  const [error, setError] = useState('')
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'

  const stats = useMemo(() => {
    const counts = summary?.level_counts || {}

    return {
      total: summary?.total || 0,
      critical: counts.critical || 0,
      high: counts.high || 0,
      medium: counts.medium || 0,
      candidates: summary?.auto_block_candidates || 0,
    }
  }, [summary])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target

    setFilters((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  const loadAlerts = async ({ silent = false } = {}) => {
    if (!selectedFirewall?.id || loadingRef.current) return

    try {
      loadingRef.current = true
      if (!silent) setLoading(true)
      setError('')

      const params = new URLSearchParams({
        minutes: String(filters.minutes),
        size: String(filters.size),
        min_risk: String(filters.minRisk),
        include_all_events: filters.includeAllEvents ? 'true' : 'false',
      })

      const res = await fetch(
        `${API_BASE}/api/firewalls/${selectedFirewall.id}/security-alerts?${params.toString()}`,
      )
      const data = await res.json()

      if (!res.ok) {
        throw new Error(data?.detail || data?.message || '공격 알림 조회 실패')
      }

      setAlerts(Array.isArray(data.rows) ? data.rows : [])
      setSummary(data.summary || null)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setError(err.message || '공격 알림 조회 실패')
    } finally {
      loadingRef.current = false
      if (!silent) setLoading(false)
    }
  }

  const blockAlert = async (alert) => {
    if (!selectedFirewall?.id || !alert?.id) return

    const sourceIp = alert.source_ip

    if (!sourceIp || sourceIp === '-') {
      setError('차단할 공격자 IP가 없습니다.')
      return
    }

    const ok = window.confirm(
      `${sourceIp} 를 ${filters.aliasName} Alias에 추가해서 차단 후보로 등록할까요?`,
    )

    if (!ok) return

    try {
      setBlockingId(alert.id)
      setError('')

      const res = await fetch(
        `${API_BASE}/api/firewalls/${selectedFirewall.id}/security-alerts/${alert.id}/block`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            source_ip: sourceIp,
            alias_name: filters.aliasName || 'blocked_attackers',
            reason: `risk score ${alert.risk?.score || 0} / ${alert.signature || 'security alert'}`,
            force: filters.forcePrivateBlock,
          }),
        },
      )

      const data = await res.json()

      if (!res.ok) {
        throw new Error(
          typeof data?.detail === 'string'
            ? data.detail
            : data?.detail?.message || data?.message || '차단 요청 실패',
        )
      }

      await loadAlerts({ silent: true })
    } catch (err) {
      setError(err.message || '차단 요청 실패')
    } finally {
      setBlockingId('')
    }
  }

  useEffect(() => {
    loadAlerts()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall])

  useEffect(() => {
    if (!filters.autoRefresh || !selectedFirewall?.id) return

    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadAlerts({ silent: true })
      }
    }, 5000)

    return () => clearInterval(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    filters.autoRefresh,
    selectedFirewall?.id,
    filters.minutes,
    filters.size,
    filters.minRisk,
    filters.includeAllEvents,
  ])

  return (
    <div className="sec-alert-page">
      <section className="sec-alert-hero">
        <div>
          <p className="sec-alert-eyebrow">ML / Risk Based Security Response</p>
          <h2>실시간 공격 알림 및 자동 대응</h2>
          <span>
            현재 대상: {selectedName}
            {lastUpdatedAt ? ` / 마지막 갱신: ${lastUpdatedAt.toLocaleTimeString()}` : ''}
          </span>
        </div>

        <div className={`sec-alert-status ${loading ? 'loading' : 'ready'}`}>
          <i />
          {loading ? '분석 중...' : '실시간 감시 중'}
        </div>
      </section>

      {error ? <div className="sec-alert-error">에러: {error}</div> : null}

      <section className="sec-alert-toolbar">
        <div className="sec-alert-filter-grid">
          <label>
            조회 범위
            <select name="minutes" value={filters.minutes} onChange={handleChange}>
              <option value="5">최근 5분</option>
              <option value="15">최근 15분</option>
              <option value="60">최근 1시간</option>
              <option value="360">최근 6시간</option>
              <option value="1440">최근 24시간</option>
            </select>
          </label>

          <label>
            조회 개수
            <select name="size" value={filters.size} onChange={handleChange}>
              <option value="100">100개</option>
              <option value="200">200개</option>
              <option value="500">500개</option>
            </select>
          </label>

          <label>
            최소 위험도
            <select name="minRisk" value={filters.minRisk} onChange={handleChange}>
              <option value="0">전체</option>
              <option value="40">중간 이상</option>
              <option value="70">높음 이상</option>
              <option value="90">매우 높음</option>
            </select>
          </label>

          <label>
            차단 Alias
            <input
              name="aliasName"
              value={filters.aliasName}
              onChange={handleChange}
              placeholder="blocked_attackers"
            />
          </label>

          <label className="sec-alert-check">
            <input
              type="checkbox"
              name="autoRefresh"
              checked={filters.autoRefresh}
              onChange={handleChange}
            />
            자동 갱신
          </label>

          <label className="sec-alert-check">
            <input
              type="checkbox"
              name="includeAllEvents"
              checked={filters.includeAllEvents}
              onChange={handleChange}
            />
            전체 이벤트 포함
          </label>

          <label className="sec-alert-check danger">
            <input
              type="checkbox"
              name="forcePrivateBlock"
              checked={filters.forcePrivateBlock}
              onChange={handleChange}
            />
            사설 IP 강제 차단
          </label>
        </div>

        <div className="sec-alert-actions">
          <button type="button" onClick={() => loadAlerts()} disabled={loading}>
            {loading ? '조회 중...' : '지금 분석'}
          </button>
        </div>
      </section>

      <section className="sec-alert-stats">
        <article>
          <span>탐지 알림</span>
          <strong>{stats.total.toLocaleString()}</strong>
        </article>
        <article className="critical">
          <span>매우 높음</span>
          <strong>{stats.critical.toLocaleString()}</strong>
        </article>
        <article className="high">
          <span>높음</span>
          <strong>{stats.high.toLocaleString()}</strong>
        </article>
        <article className="candidate">
          <span>차단 후보</span>
          <strong>{stats.candidates.toLocaleString()}</strong>
        </article>
      </section>

      <section className="sec-alert-card">
        <div className="sec-alert-card-header">
          <div>
            <p className="sec-alert-eyebrow">Realtime Alerts</p>
            <h3>공격 탐지 목록</h3>
          </div>

          <span>{alerts.length.toLocaleString()}건</span>
        </div>

        <div className="sec-alert-table-wrap">
          <table className="sec-alert-table">
            <thead>
              <tr>
                <th>시간</th>
                <th>위험도</th>
                <th>상태</th>
                <th>공격자</th>
                <th>대상</th>
                <th>프로토콜</th>
                <th>시그니처</th>
                <th>분류</th>
                <th>대응</th>
              </tr>
            </thead>

            <tbody>
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan="9" className="sec-alert-empty">
                    표시할 공격 알림이 없습니다.
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => {
                  const level = alert.risk?.level || 'low'

                  return (
                    <tr key={alert.id}>
                      <td>{toText(alert.timestamp)}</td>
                      <td>
                        <span className={`sec-risk-badge ${level}`}>
                          {alert.risk?.score ?? 0}점 ·{' '}
                          {LEVEL_LABELS[level] || alert.risk?.label || '-'}
                        </span>
                      </td>
                      <td>
                        <span className={`sec-status-badge ${alert.status || 'detected'}`}>
                          {STATUS_LABELS[alert.status] || alert.status}
                        </span>
                      </td>
                      <td>{toText(alert.source_ip)}:{toText(alert.source_port, '')}</td>
                      <td>
                        {toText(alert.destination_ip)}:
                        {toText(alert.destination_port, '')}
                      </td>
                      <td>{toText(alert.protocol)}</td>
                      <td className="sec-alert-signature">{toText(alert.signature)}</td>
                      <td>{toText(alert.category)}</td>
                      <td>
                        <div className="sec-alert-row-actions">
                          <button type="button" onClick={() => setSelectedAlert(alert)}>
                            상세
                          </button>
                          <button
                            type="button"
                            className="danger"
                            onClick={() => blockAlert(alert)}
                            disabled={blockingId === alert.id || alert.status === 'blocked'}
                          >
                            {alert.status === 'blocked'
                              ? '차단됨'
                              : blockingId === alert.id
                                ? '차단 중...'
                                : '차단'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      <AlertDetailModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  )
}

export default SecurityAlertsPage
