import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

import Sidebar from './components/layout/Sidebar'
import DashboardPage from './pages/DashboardPage'
import FirewallEventLogsPage from './pages/FirewallEventLogsPage'
import FirewallManagerPage from './pages/FirewallManagerPage'
import LogsPage from './pages/LogsPage'
import RulesPage from './pages/RulesPage'

const API_BASE = 'http://127.0.0.1:8000'
const TRAFFIC_HISTORY_LIMIT = 20

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [dashboard, setDashboard] = useState(null)
  const [trafficHistory, setTrafficHistory] = useState([])
  const [currentInterfaceStats, setCurrentInterfaceStats] = useState([])
  const [firewalls, setFirewalls] = useState([])
  const [selectedFirewallId, setSelectedFirewallId] = useState(null)
  const lastTrafficRef = useRef(null)

  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [logs, setLogs] = useState([
    {
      id: 1,
      time: new Date().toLocaleString(),
      level: 'INFO',
      message: '대시보드 초기화 완료',
    },
  ])
  const [form, setForm] = useState({
    description: '',
    action: 'pass',
    interface: 'lan',
    direction: 'in',
    protocol: 'TCP',
    sourceNet: 'any',
    sourcePort: '',
    destinationNet: 'any',
    destinationPort: '',
    enabled: '1',
    quick: '1',
    log: false,
  })

  const selectedFirewall = useMemo(
    () => firewalls.find((fw) => fw.id === selectedFirewallId) || null,
    [firewalls, selectedFirewallId],
  )

  const addLog = (level, message) =>
    setLogs((prev) => [
      {
        id: Date.now() + Math.random(),
        time: new Date().toLocaleString(),
        level,
        message,
      },
      ...prev,
    ])
  const parseErrorMessage = (data, fallback) => {
    if (!data) return fallback
    if (typeof data === 'string') return data
    if (data.detail?.message) return data.detail.message
    if (typeof data.detail === 'string') return data.detail
    if (data.message) return data.message
    if (data.error) return data.error
    return fallback
  }
  const toNumber = (value) => {
    if (value == null) return 0
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0
    const cleaned = String(value).replace(/[^\d.-]/g, '')
    const num = Number(cleaned)
    return Number.isFinite(num) ? num : 0
  }

  const normalizeTrafficRows = (traffic) => {
    if (!traffic) return []
    if (Array.isArray(traffic)) return traffic
    if (Array.isArray(traffic?.rows)) return traffic.rows
    if (Array.isArray(traffic?.interfaces)) return traffic.interfaces
    if (Array.isArray(traffic?.data)) return traffic.data
    if (traffic?.statistics && typeof traffic.statistics === 'object') {
      return Object.entries(traffic.statistics).map(([rawKey, value]) => {
        let iface = rawKey
        if (rawKey.includes('(em0)')) iface = 'em0'
        else if (rawKey.includes('(em1)')) iface = 'em1'
        else if (rawKey.includes('(em2)')) iface = 'em2'
        else if (rawKey.includes('(lo0)')) iface = 'lo0'
        return {
          name: iface,
          rawKey,
          ...(typeof value === 'object' ? value : { value }),
        }
      })
    }
    if (typeof traffic === 'object')
      return Object.entries(traffic)
        .filter(([key]) => key !== 'error')
        .map(([name, value]) => ({
          name,
          ...(typeof value === 'object' ? value : { value }),
        }))
    return []
  }

  const extractInterfaceGroupLabel = (rawName) => {
    if (!rawName) return 'UNKNOWN'
    if (rawName.includes('em0')) return 'WAN'
    if (rawName.includes('em1')) return 'LAN'
    if (rawName.includes('em2')) return 'OPT1'
    if (rawName.includes('lo0')) return 'LOOPBACK'
    return rawName
  }

  const extractInterfaceCounters = (row) => {
    const source = row || {}
    const entries = Object.entries(source)
    const findMetric = (patterns) => {
      for (const [rawKey, rawValue] of entries) {
        const key = String(rawKey)
          .toLowerCase()
          .replace(/[\s_\-:/()[\].]/g, '')
        if (patterns.some((pattern) => key.includes(pattern)))
          return toNumber(rawValue)
      }
      return 0
    }
    return {
      rxBytes: findMetric([
        'bytesreceived',
        'receivedbytes',
        'rxbytes',
        'inbytes',
        'ibytes',
        'bytesin',
      ]),
      txBytes: findMetric([
        'bytestransmitted',
        'transmittedbytes',
        'txbytes',
        'outbytes',
        'obytes',
        'bytesout',
        'sentbytes',
        'sendbytes',
      ]),
      rxPackets: findMetric([
        'packetsreceived',
        'receivedpackets',
        'rxpackets',
        'inpackets',
        'inpkts',
        'ipackets',
        'packetsin',
      ]),
      txPackets: findMetric([
        'packetstransmitted',
        'transmittedpackets',
        'txpackets',
        'outpackets',
        'outpkts',
        'opackets',
        'packetsout',
        'sentpackets',
        'sendpackets',
      ]),
      rxErrors: findMetric(['inputerrors', 'rxerrors', 'ierrors']),
      txErrors: findMetric(['outputerrors', 'txerrors', 'oerrors']),
      collisions: findMetric(['collisions', 'colls']),
    }
  }

  const buildCurrentInterfaceStats = (rows) => {
    const grouped = {}
    rows.forEach((row, index) => {
      const label = extractInterfaceGroupLabel(
        row?.name || `interface-${index + 1}`,
      )
      const counters = extractInterfaceCounters(row)
      if (!grouped[label])
        grouped[label] = {
          id: label,
          label,
          interface: label,
          rxBytes: 0,
          txBytes: 0,
          rxPackets: 0,
          txPackets: 0,
          rxErrors: 0,
          txErrors: 0,
          collisions: 0,
          totalBytes: 0,
          totalPackets: 0,
        }
      grouped[label].rxBytes += counters.rxBytes
      grouped[label].txBytes += counters.txBytes
      grouped[label].rxPackets += counters.rxPackets
      grouped[label].txPackets += counters.txPackets
      grouped[label].totalBytes =
        grouped[label].rxBytes + grouped[label].txBytes
      grouped[label].totalPackets =
        grouped[label].rxPackets + grouped[label].txPackets
    })
    return Object.values(grouped).filter(
      (x) => x.totalBytes > 0 || x.totalPackets > 0,
    )
  }

  const updateTrafficRateHistory = (traffic) => {
    const rows = normalizeTrafficRows(traffic)
    const currentStats = buildCurrentInterfaceStats(rows)
    setCurrentInterfaceStats(currentStats)
    const now = Date.now()
    const prev = lastTrafficRef.current
    const currentMap = {}
    currentStats.forEach((item) => {
      currentMap[item.interface] = item
    })
    if (!prev) {
      lastTrafficRef.current = { timestamp: now, interfaces: currentMap }
      return
    }
    const elapsedSeconds = Math.max((now - prev.timestamp) / 1000, 1)
    const interfaceNames = Array.from(
      new Set([
        ...Object.keys(prev.interfaces || {}),
        ...Object.keys(currentMap || {}),
      ]),
    )
    const nextPoint = {
      time: new Date(now).toLocaleTimeString(),
      timestamp: now,
    }
    interfaceNames.forEach((name) => {
      const prevItem = prev.interfaces?.[name]
      const currentItem = currentMap?.[name]
      const prevRx =
        prevItem?.rxBytes > 0 ? prevItem.rxBytes : prevItem?.rxPackets || 0
      const currentRx =
        currentItem?.rxBytes > 0
          ? currentItem.rxBytes
          : currentItem?.rxPackets || 0
      const prevTx =
        prevItem?.txBytes > 0 ? prevItem.txBytes : prevItem?.txPackets || 0
      const currentTx =
        currentItem?.txBytes > 0
          ? currentItem.txBytes
          : currentItem?.txPackets || 0
      nextPoint[`rx_${name}`] = Math.max(currentRx - prevRx, 0) / elapsedSeconds
      nextPoint[`tx_${name}`] = Math.max(currentTx - prevTx, 0) / elapsedSeconds
    })
    setTrafficHistory((prevHistory) =>
      [...prevHistory, nextPoint].slice(-TRAFFIC_HISTORY_LIMIT),
    )
    lastTrafficRef.current = { timestamp: now, interfaces: currentMap }
  }

  const fetchFirewalls = async () => {
    const res = await fetch(`${API_BASE}/api/firewalls`)
    const data = await res.json()
    if (!res.ok)
      throw new Error(parseErrorMessage(data, '방화벽 목록 조회 실패'))
    setFirewalls(Array.isArray(data) ? data : [])
    if (!selectedFirewallId && Array.isArray(data) && data.length > 0)
      setSelectedFirewallId(data[0].id)
  }

  const fetchDashboard = async () => {
    if (!selectedFirewallId) return
    try {
      setLoading(true)
      setError('')
      const res = await fetch(
        `${API_BASE}/api/firewalls/${selectedFirewallId}/dashboard`,
      )
      const data = await res.json()
      if (!res.ok)
        throw new Error(parseErrorMessage(data, '대시보드 조회 실패'))
      setDashboard(data)
      updateTrafficRateHistory(data?.traffic)
      addLog('INFO', `${data?.firewall?.name || '방화벽'} 대시보드 갱신 완료`)
    } catch (err) {
      const msg = err.message || '대시보드를 불러오지 못했습니다.'
      setError(msg)
      addLog('ERROR', msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFirewalls().catch((e) => setError(e.message))
  }, [])
  useEffect(() => {
    fetchDashboard()
  }, [selectedFirewallId])
  useEffect(() => {
    if (!autoRefresh || !selectedFirewallId) return
    const interval = setInterval(fetchDashboard, 5000)
    return () => clearInterval(interval)
  }, [autoRefresh, selectedFirewallId])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }
  const resetForm = () =>
    setForm({
      description: '',
      action: 'pass',
      interface: 'lan',
      direction: 'in',
      protocol: 'TCP',
      sourceNet: 'any',
      sourcePort: '',
      destinationNet: 'any',
      destinationPort: '',
      enabled: '1',
      quick: '1',
      log: false,
    })
  const onCreateFirewall = async (payload) => {
    const res = await fetch(`${API_BASE}/api/firewalls`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 등록 실패'))
    await fetchFirewalls()
    setSelectedFirewallId(data.id)
    addLog('INFO', `방화벽 등록: ${data.name}`)
  }
  const onDeleteFirewall = async (firewallId) => {
    if (!window.confirm('정말 삭제할까요?')) return
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}`, {
      method: 'DELETE',
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 삭제 실패'))
    await fetchFirewalls()
    if (selectedFirewallId === firewallId) setSelectedFirewallId(null)
    addLog('WARN', `방화벽 삭제: ${firewallId}`)
  }
  const handleAddRule = async (e) => {
    e.preventDefault()
    if (!selectedFirewallId) return
    try {
      setSubmitting(true)
      const res = await fetch(
        `${API_BASE}/api/firewalls/${selectedFirewallId}/rules`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(form),
        },
      )
      const data = await res.json()
      if (!res.ok) throw new Error(parseErrorMessage(data, '룰 추가 실패'))
      addLog('INFO', `룰 추가 성공: ${form.description || '설명 없음'}`)
      resetForm()
      await fetchDashboard()
      setCurrentPage('rules')
    } catch (err) {
      const msg = err.message || '룰 추가 중 오류'
      setError(msg)
      addLog('ERROR', msg)
    } finally {
      setSubmitting(false)
    }
  }
  const handleDeleteRule = async (uuid, description) => {
    if (!selectedFirewallId || !uuid) return
    if (!window.confirm(`정말 삭제할까요?\n\n${description || '설명 없음'}`))
      return
    try {
      const res = await fetch(
        `${API_BASE}/api/firewalls/${selectedFirewallId}/rules/${uuid}`,
        { method: 'DELETE' },
      )
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(parseErrorMessage(data, '룰 삭제 실패'))
      addLog('WARN', `룰 삭제 성공: ${description || uuid}`)
      await fetchDashboard()
    } catch (err) {
      const msg = err.message || '룰 삭제 오류'
      setError(msg)
      addLog('ERROR', msg)
    }
  }
  const fetchEventLogs = async (filters) => {
    if (!selectedFirewallId) throw new Error('방화벽을 먼저 선택하세요.')
    const res = await fetch(
      `${API_BASE}/api/firewalls/${selectedFirewallId}/event-logs`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(filters),
      },
    )
    const data = await res.json()
    if (!res.ok)
      throw new Error(parseErrorMessage(data, '이벤트 로그 조회 실패'))
    return data
  }

  const rules = Array.isArray(dashboard?.rules?.rows)
    ? dashboard.rules.rows
    : []
  const aliasesRaw = dashboard?.aliases
  const aliases = Array.isArray(aliasesRaw)
    ? aliasesRaw
    : Array.isArray(aliasesRaw?.rows)
      ? aliasesRaw.rows
      : []

  return (
    <div className="app-shell">
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />
      <main className="content">
        <div className="top-actions page-tools">
          <button
            onClick={fetchDashboard}
            disabled={loading || !selectedFirewallId}
          >
            {loading ? '불러오는 중...' : '🔄 새로고침'}
          </button>
          <label className="checkbox-inline">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            자동 갱신(5초)
          </label>
          <select
            value={selectedFirewallId || ''}
            onChange={(e) =>
              setSelectedFirewallId(Number(e.target.value) || null)
            }
          >
            <option value="">방화벽 선택</option>
            {firewalls.map((fw) => (
              <option key={fw.id} value={fw.id}>
                {fw.name}
              </option>
            ))}
          </select>
          <span className="rule-count">
            현재 대상: {selectedFirewall?.name || '없음'}
          </span>
        </div>
        {error && <div className="error card">에러: {error}</div>}
        {currentPage === 'dashboard' && (
          <DashboardPage
            product={dashboard?.product || dashboard?.status?.product || null}
            status={dashboard?.status || null}
            system={dashboard?.system || null}
            systemSummary={dashboard?.system_summary || null}
            interfaces={dashboard?.interfaces || null}
            services={dashboard?.services || null}
            traffic={dashboard?.traffic || null}
            memory={dashboard?.memory || null}
            memorySummary={dashboard?.memory_summary || null}
            disk={dashboard?.disk || null}
            diskSummary={dashboard?.disk_summary || null}
            rules={rules}
            aliases={aliases}
            autoRefresh={autoRefresh}
            loading={loading}
            trafficHistory={trafficHistory}
            currentInterfaceStats={currentInterfaceStats}
          />
        )}
        {currentPage === 'rules' && (
          <RulesPage
            rules={rules}
            form={form}
            setForm={setForm}
            showAdvanced={showAdvanced}
            setShowAdvanced={setShowAdvanced}
            submitting={submitting}
            handleChange={handleChange}
            handleAddRule={handleAddRule}
            handleDeleteRule={handleDeleteRule}
            resetForm={resetForm}
            selectedFirewall={selectedFirewall}
          />
        )}
        {currentPage === 'eventLogs' && (
          <FirewallEventLogsPage
            selectedFirewall={selectedFirewall}
            fetchEventLogs={fetchEventLogs}
          />
        )}
        {currentPage === 'firewalls' && (
          <FirewallManagerPage
            firewalls={firewalls}
            selectedFirewallId={selectedFirewallId}
            setSelectedFirewallId={setSelectedFirewallId}
            onCreateFirewall={onCreateFirewall}
            onDeleteFirewall={onDeleteFirewall}
          />
        )}
        {currentPage === 'logs' && <LogsPage logs={logs} setLogs={setLogs} />}
      </main>
    </div>
  )
}

export default App
