
import { useEffect, useMemo, useRef, useState } from 'react'
import './App.css'

import Sidebar from './components/layout/Sidebar'
import DashboardPage from './pages/DashboardPage'
import RulesPage from './pages/RulesPage'
import LogsPage from './pages/LogsPage'
import FirewallManagerPage from './pages/FirewallManagerPage'

const API_BASE = 'http://127.0.0.1:8000'
const TRAFFIC_HISTORY_LIMIT = 20

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [firewalls, setFirewalls] = useState([])
  const [selectedFirewallId, setSelectedFirewallId] = useState(null)
  const [dashboard, setDashboard] = useState(null)
  const [trafficHistory, setTrafficHistory] = useState([])
  const [currentInterfaceStats, setCurrentInterfaceStats] = useState([])
  const lastTrafficRef = useRef(null)

  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [submitting, setSubmitting] = useState(false)

  const [logs, setLogs] = useState([
    { id: 1, time: new Date().toLocaleString(), level: 'INFO', message: '대시보드 초기화 완료' },
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

  const addLog = (level, message) => {
    setLogs((prev) => [
      { id: Date.now() + Math.random(), time: new Date().toLocaleString(), level, message },
      ...prev,
    ])
  }

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
    if (value === null || value === undefined) return 0
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
        else if (rawKey.includes('(enc0)')) iface = 'enc0'
        else if (rawKey.includes('(pfsync0)')) iface = 'pfsync0'
        else if (rawKey.includes('(pflog0)')) iface = 'pflog0'
        return { name: iface, rawKey, ...(typeof value === 'object' ? value : { value }) }
      })
    }

    if (typeof traffic === 'object') {
      return Object.entries(traffic)
        .filter(([key]) => key !== 'error')
        .map(([name, value]) => ({ name, ...(typeof value === 'object' ? value : { value }) }))
    }
    return []
  }

  const extractInterfaceGroupLabel = (rawName) => {
    if (!rawName) return 'UNKNOWN'
    if (rawName.includes('em0')) return 'WAN'
    if (rawName.includes('em1')) return 'LAN'
    if (rawName.includes('em2')) return 'OPT1'
    if (rawName.includes('lo0')) return 'LOOPBACK'
    if (rawName.includes('enc0')) return 'ENC'
    if (rawName.includes('pfsync0')) return 'PFSYNC'
    if (rawName.includes('pflog0')) return 'PFLOG'
    return rawName
  }

  const extractInterfaceCounters = (row) => {
    const source = row || {}
    const entries = Object.entries(source)

    const findMetric = (patterns) => {
      for (const [rawKey, rawValue] of entries) {
        const key = String(rawKey).toLowerCase().replace(/[\s_\-:/()[\].]/g, '')
        if (patterns.some((pattern) => key.includes(pattern))) {
          const value = toNumber(rawValue)
          if (value || value === 0) return value
        }
      }
      return 0
    }

    return {
      rxBytes: findMetric(['bytesreceived', 'receivedbytes', 'rxbytes', 'inbytes', 'ibytes', 'bytesin']),
      txBytes: findMetric(['bytestransmitted', 'transmittedbytes', 'txbytes', 'outbytes', 'obytes', 'bytesout', 'sentbytes', 'sendbytes']),
      rxPackets: findMetric(['packetsreceived', 'receivedpackets', 'rxpackets', 'inpackets', 'inpkts', 'ipackets', 'packetsin']),
      txPackets: findMetric(['packetstransmitted', 'transmittedpackets', 'txpackets', 'outpackets', 'outpkts', 'opackets', 'packetsout', 'sentpackets', 'sendpackets']),
      rxErrors: findMetric(['inputerrors', 'rxerrors', 'ierrors']),
      txErrors: findMetric(['outputerrors', 'txerrors', 'oerrors']),
      collisions: findMetric(['collisions', 'colls']),
    }
  }

  const buildCurrentInterfaceStats = (rows) => {
    const grouped = {}
    rows.forEach((row, index) => {
      const rawName = row?.name || `interface-${index + 1}`
      const label = extractInterfaceGroupLabel(rawName)
      const iface = label
      const counters = extractInterfaceCounters(row)

      if (!grouped[iface]) {
        grouped[iface] = {
          id: iface,
          label,
          interface: iface,
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
      }

      grouped[iface].rxBytes += counters.rxBytes
      grouped[iface].txBytes += counters.txBytes
      grouped[iface].rxPackets += counters.rxPackets
      grouped[iface].txPackets += counters.txPackets
      grouped[iface].rxErrors += counters.rxErrors
      grouped[iface].txErrors += counters.txErrors
      grouped[iface].collisions += counters.collisions
      grouped[iface].totalBytes = grouped[iface].rxBytes + grouped[iface].txBytes
      grouped[iface].totalPackets = grouped[iface].rxPackets + grouped[iface].txPackets
    })

    return Object.values(grouped).filter(
      (item) => item.totalBytes > 0 || item.totalPackets > 0 || item.rxErrors > 0 || item.txErrors > 0,
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
    const interfaceNames = Array.from(new Set([...Object.keys(prev.interfaces || {}), ...Object.keys(currentMap || {})]))
    const nextPoint = { time: new Date(now).toLocaleTimeString(), timestamp: now }

    interfaceNames.forEach((name) => {
      const prevItem = prev.interfaces?.[name]
      const currentItem = currentMap?.[name]

      const prevRx = prevItem?.rxBytes && prevItem.rxBytes > 0 ? prevItem.rxBytes : (prevItem?.rxPackets || 0)
      const currentRx = currentItem?.rxBytes && currentItem.rxBytes > 0 ? currentItem.rxBytes : (currentItem?.rxPackets || 0)
      const prevTx = prevItem?.txBytes && prevItem.txBytes > 0 ? prevItem.txBytes : (prevItem?.txPackets || 0)
      const currentTx = currentItem?.txBytes && currentItem.txBytes > 0 ? currentItem.txBytes : (currentItem?.txPackets || 0)

      nextPoint[`rx_${name}`] = Math.max(currentRx - prevRx, 0) / elapsedSeconds
      nextPoint[`tx_${name}`] = Math.max(currentTx - prevTx, 0) / elapsedSeconds
    })

    setTrafficHistory((prevHistory) => [...prevHistory, nextPoint].slice(-TRAFFIC_HISTORY_LIMIT))
    lastTrafficRef.current = { timestamp: now, interfaces: currentMap }
  }

  const fetchFirewalls = async () => {
    const res = await fetch(`${API_BASE}/api/firewalls`)
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 목록 조회 실패'))
    setFirewalls(data.items || [])
    setSelectedFirewallId((prev) => prev ?? data.selectedFirewallId ?? data.items?.[0]?.id ?? null)
  }

  const fetchDashboard = async (firewallId = selectedFirewallId) => {
    if (!firewallId) {
      setDashboard(null)
      setTrafficHistory([])
      setCurrentInterfaceStats([])
      return
    }

    try {
      setLoading(true)
      setError('')
      const res = await fetch(`${API_BASE}/api/opnsense/dashboard/${firewallId}`)
      const data = await res.json()
      if (!res.ok) throw new Error(parseErrorMessage(data, '대시보드 조회 실패'))
      setDashboard(data)
      updateTrafficRateHistory(data?.traffic)
      addLog('INFO', `${data?.firewall?.name || '선택된 방화벽'} 대시보드 갱신 완료`)
    } catch (err) {
      const msg = err.message || '대시보드를 불러오지 못했습니다.'
      setError(msg)
      addLog('ERROR', msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchFirewalls().catch((err) => setError(err.message))
  }, [])

  useEffect(() => {
    if (!selectedFirewallId) return
    lastTrafficRef.current = null
    setTrafficHistory([])
    fetchDashboard(selectedFirewallId)
  }, [selectedFirewallId])

  useEffect(() => {
    if (!autoRefresh || !selectedFirewallId) return
    const interval = setInterval(() => fetchDashboard(selectedFirewallId), 5000)
    return () => clearInterval(interval)
  }, [autoRefresh, selectedFirewallId])

  const handleSelectFirewall = async (firewallId) => {
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}/select`, { method: 'POST' })
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 선택 실패'))
    setSelectedFirewallId(firewallId)
  }

  const handleCreateFirewall = async (payload) => {
    const res = await fetch(`${API_BASE}/api/firewalls`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 등록 실패'))
    await fetchFirewalls()
    if (data?.item?.id) setSelectedFirewallId(data.item.id)
    addLog('INFO', `${payload.name} 방화벽 등록 완료`)
  }

  const handleDeleteFirewall = async (firewallId) => {
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}`, { method: 'DELETE' })
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '방화벽 삭제 실패'))
    await fetchFirewalls()
    setSelectedFirewallId(data.selectedFirewallId || null)
    addLog('WARN', '방화벽 삭제 완료')
  }

  const handleTestFirewall = async (firewallId) => {
    const res = await fetch(`${API_BASE}/api/firewalls/${firewallId}/test`, { method: 'POST' })
    const data = await res.json()
    if (!res.ok) throw new Error(parseErrorMessage(data, '연결 테스트 실패'))
    addLog('INFO', '방화벽 연결 테스트 성공')
    return data
  }

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({ ...prev, [name]: type === 'checkbox' ? checked : value }))
  }

  const resetForm = () => {
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
  }

  const handleAddRule = async (e) => {
    e.preventDefault()
    if (!selectedFirewallId) {
      alert('먼저 방화벽을 선택해줘.')
      return
    }

    try {
      setSubmitting(true)
      setError('')
      const res = await fetch(`${API_BASE}/api/opnsense/rules/${selectedFirewallId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(parseErrorMessage(data, '룰 추가 실패'))

      addLog('INFO', `${selectedFirewall?.name || '방화벽'}에 룰 추가 성공`)
      alert('✅ 룰이 추가되었습니다.')
      resetForm()
      await fetchDashboard(selectedFirewallId)
      setCurrentPage('rules')
    } catch (err) {
      const msg = err.message || '룰 추가 중 오류가 발생했습니다.'
      setError(msg)
      addLog('ERROR', `룰 추가 실패: ${msg}`)
      alert(`❌ ${msg}`)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDeleteRule = async (uuid, description) => {
    if (!selectedFirewallId) return
    const ok = window.confirm(`정말 삭제할까요?\n대상: ${selectedFirewall?.name || '선택된 방화벽'}\n\n${description || '설명 없음'}`)
    if (!ok) return

    try {
      setError('')
      const res = await fetch(`${API_BASE}/api/opnsense/rules/${selectedFirewallId}/${uuid}`, { method: 'DELETE' })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(parseErrorMessage(data, '룰 삭제 실패'))

      addLog('WARN', `${selectedFirewall?.name || '방화벽'}에서 룰 삭제 성공`)
      alert('🗑️ 룰이 삭제되었습니다.')
      await fetchDashboard(selectedFirewallId)
    } catch (err) {
      const msg = err.message || '룰 삭제 중 오류가 발생했습니다.'
      setError(msg)
      addLog('ERROR', `룰 삭제 실패: ${msg}`)
      alert(`❌ ${msg}`)
    }
  }

  const product = dashboard?.product || dashboard?.status?.product || null
  const status = dashboard?.status || null
  const rules = Array.isArray(dashboard?.rules?.rows) ? dashboard.rules.rows : []
  const system = dashboard?.system || null
  const systemSummary = dashboard?.system_summary || null
  const interfaces = dashboard?.interfaces || null
  const services = dashboard?.services || null
  const traffic = dashboard?.traffic || null
  const memory = dashboard?.memory || null
  const memorySummary = dashboard?.memory_summary || null
  const disk = dashboard?.disk || null
  const diskSummary = dashboard?.disk_summary || null
  const aliasesRaw = dashboard?.aliases
  const aliases = Array.isArray(aliasesRaw) ? aliasesRaw : Array.isArray(aliasesRaw?.rows) ? aliasesRaw.rows : []

  return (
    <div className="app-shell">
      <Sidebar currentPage={currentPage} setCurrentPage={setCurrentPage} />

      <main className="content">
        <div className="top-actions page-tools">
          <button onClick={() => fetchDashboard()} disabled={loading || !selectedFirewallId}>
            {loading ? '불러오는 중...' : '🔄 새로고침'}
          </button>

          <label className="checkbox-inline">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            자동 갱신(5초)
          </label>

          <div className="selected-firewall-chip">
            현재 대상: <strong>{selectedFirewall?.name || '선택 없음'}</strong>
          </div>
        </div>

        {error && <div className="error card">에러: {error}</div>}

        {!selectedFirewallId && currentPage !== 'firewalls' && (
          <div className="card empty-state">
            <h3>등록된 방화벽이 없어요</h3>
            <p>먼저 방화벽을 등록한 뒤 대시보드를 사용할 수 있어.</p>
            <button onClick={() => setCurrentPage('firewalls')}>방화벽 등록하기</button>
          </div>
        )}

        {currentPage === 'dashboard' && selectedFirewallId && (
          <DashboardPage
            product={product}
            status={status}
            system={system}
            systemSummary={systemSummary}
            interfaces={interfaces}
            services={services}
            traffic={traffic}
            memory={memory}
            memorySummary={memorySummary}
            disk={disk}
            diskSummary={diskSummary}
            rules={rules}
            aliases={aliases}
            autoRefresh={autoRefresh}
            loading={loading}
            trafficHistory={trafficHistory}
            currentInterfaceStats={currentInterfaceStats}
            selectedFirewall={selectedFirewall}
          />
        )}

        {currentPage === 'rules' && selectedFirewallId && (
          <RulesPage
            rules={rules}
            loading={loading}
            form={form}
            setForm={setForm}
            showAdvanced={showAdvanced}
            setShowAdvanced={setShowAdvanced}
            submitting={submitting}
            handleChange={handleChange}
            handleAddRule={handleAddRule}
            handleDeleteRule={handleDeleteRule}
            resetForm={resetForm}
            aliases={aliases}
            selectedFirewall={selectedFirewall}
          />
        )}

        {currentPage === 'logs' && <LogsPage logs={logs} setLogs={setLogs} />}

        {currentPage === 'firewalls' && (
          <FirewallManagerPage
            items={firewalls}
            selectedFirewallId={selectedFirewallId}
            onSelect={handleSelectFirewall}
            onCreate={handleCreateFirewall}
            onDelete={handleDeleteFirewall}
            onTest={handleTestFirewall}
          />
        )}
      </main>
    </div>
  )
}

export default App
