import { useEffect, useRef, useState } from 'react'
import './App.css'

import Sidebar from './components/layout/Sidebar'
import DashboardPage from './pages/DashboardPage'
import RulesPage from './pages/RulesPage'
import LogsPage from './pages/LogsPage'

const API_BASE = 'http://127.0.0.1:8000'
const TRAFFIC_HISTORY_LIMIT = 20

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
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

  const addLog = (level, message) => {
    setLogs((prev) => [
      {
        id: Date.now() + Math.random(),
        time: new Date().toLocaleString(),
        level,
        message,
      },
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
    console.log('[normalizeTrafficRows] 원본 traffic:', traffic)

    if (!traffic) {
      console.log('[normalizeTrafficRows] traffic 없음')
      return []
    }

    if (Array.isArray(traffic)) {
      console.log('[normalizeTrafficRows] traffic 자체가 배열:', traffic)
      return traffic
    }

    if (Array.isArray(traffic?.rows)) {
      console.log('[normalizeTrafficRows] traffic.rows 사용:', traffic.rows)
      return traffic.rows
    }

    if (Array.isArray(traffic?.interfaces)) {
      console.log(
        '[normalizeTrafficRows] traffic.interfaces 사용:',
        traffic.interfaces,
      )
      return traffic.interfaces
    }

    if (Array.isArray(traffic?.data)) {
      console.log('[normalizeTrafficRows] traffic.data 사용:', traffic.data)
      return traffic.data
    }

    if (traffic?.statistics && typeof traffic.statistics === 'object') {
      const rows = Object.entries(traffic.statistics).map(([rawKey, value]) => {
        let iface = rawKey

        if (rawKey.includes('(em0)')) iface = 'em0'
        else if (rawKey.includes('(em1)')) iface = 'em1'
        else if (rawKey.includes('(em2)')) iface = 'em2'
        else if (rawKey.includes('(lo0)')) iface = 'lo0'
        else if (rawKey.includes('(enc0)')) iface = 'enc0'
        else if (rawKey.includes('(pfsync0)')) iface = 'pfsync0'
        else if (rawKey.includes('(pflog0)')) iface = 'pflog0'

        return {
          name: iface,
          rawKey,
          ...(typeof value === 'object' ? value : { value }),
        }
      })

      console.log(
        '[normalizeTrafficRows] traffic.statistics 객체 변환 결과:',
        rows,
      )
      return rows
    }

    if (typeof traffic === 'object') {
      const rows = Object.entries(traffic)
        .filter(([key]) => key !== 'error')
        .map(([name, value]) => ({
          name,
          ...(typeof value === 'object' ? value : { value }),
        }))

      console.log('[normalizeTrafficRows] 일반 객체 변환 결과:', rows)
      return rows
    }

    console.log('[normalizeTrafficRows] 어떤 조건에도 안 걸림')
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
        const key = String(rawKey)
          .toLowerCase()
          .replace(/[\s_\-:/()[\].]/g, '')

        if (patterns.some((pattern) => key.includes(pattern))) {
          const value = toNumber(rawValue)
          if (value || value === 0) {
            return value
          }
        }
      }
      return 0
    }

    const result = {
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

    console.log(
      '[extractInterfaceCounters]',
      row?.name,
      result,
      Object.keys(source),
    )

    return result
  }

  const buildCurrentInterfaceStats = (rows) => {
    console.log('[buildCurrentInterfaceStats] 입력 rows:', rows)

    const grouped = {}

    rows.forEach((row, index) => {
      const rawName = row?.name || `interface-${index + 1}`
      const label = extractInterfaceGroupLabel(rawName)
      const iface = label
      const counters = extractInterfaceCounters(row)

      console.log('[buildCurrentInterfaceStats] rawName:', rawName)
      console.log('[buildCurrentInterfaceStats] label:', label)
      console.log('[buildCurrentInterfaceStats] counters:', counters)

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
      grouped[iface].totalBytes =
        grouped[iface].rxBytes + grouped[iface].txBytes
      grouped[iface].totalPackets =
        grouped[iface].rxPackets + grouped[iface].txPackets
    })

    const result = Object.values(grouped).filter(
      (item) =>
        item.totalBytes > 0 ||
        item.totalPackets > 0 ||
        item.rxErrors > 0 ||
        item.txErrors > 0,
    )

    console.log('[buildCurrentInterfaceStats] grouped:', grouped)
    console.log('[buildCurrentInterfaceStats] 최종 result:', result)

    return result
  }

  const updateTrafficRateHistory = (traffic) => {
    console.log('[updateTrafficRateHistory] 시작 traffic:', traffic)

    const rows = normalizeTrafficRows(traffic)
    const currentStats = buildCurrentInterfaceStats(rows)
    setCurrentInterfaceStats(currentStats)

    console.log('[updateTrafficRateHistory] rows:', rows)
    console.log('[updateTrafficRateHistory] currentStats:', currentStats)

    const now = Date.now()
    const prev = lastTrafficRef.current

    const currentMap = {}
    currentStats.forEach((item) => {
      currentMap[item.interface] = item
    })

    console.log('[updateTrafficRateHistory] currentMap:', currentMap)
    console.log('[updateTrafficRateHistory] prev:', prev)

    if (!prev) {
      lastTrafficRef.current = {
        timestamp: now,
        interfaces: currentMap,
      }
      console.log('[updateTrafficRateHistory] 첫 샘플 저장만 하고 종료')
      return
    }

    const elapsedSeconds = Math.max((now - prev.timestamp) / 1000, 1)
    const interfaceNames = Array.from(
      new Set([
        ...Object.keys(prev.interfaces || {}),
        ...Object.keys(currentMap || {}),
      ]),
    )

    console.log('[updateTrafficRateHistory] elapsedSeconds:', elapsedSeconds)
    console.log('[updateTrafficRateHistory] interfaceNames:', interfaceNames)

    const nextPoint = {
      time: new Date(now).toLocaleTimeString(),
      timestamp: now,
    }

    interfaceNames.forEach((name) => {
      const prevItem = prev.interfaces?.[name]
      const currentItem = currentMap?.[name]

      const prevRx =
        prevItem?.rxBytes && prevItem.rxBytes > 0
          ? prevItem.rxBytes
          : prevItem?.rxPackets || 0

      const currentRx =
        currentItem?.rxBytes && currentItem.rxBytes > 0
          ? currentItem.rxBytes
          : currentItem?.rxPackets || 0

      const prevTx =
        prevItem?.txBytes && prevItem.txBytes > 0
          ? prevItem.txBytes
          : prevItem?.txPackets || 0

      const currentTx =
        currentItem?.txBytes && currentItem.txBytes > 0
          ? currentItem.txBytes
          : currentItem?.txPackets || 0

      const rxRate = Math.max(currentRx - prevRx, 0) / elapsedSeconds
      const txRate = Math.max(currentTx - prevTx, 0) / elapsedSeconds

      nextPoint[`rx_${name}`] = rxRate
      nextPoint[`tx_${name}`] = txRate

      console.log(`[updateTrafficRateHistory] ${name}`, {
        prevRx,
        prevTx,
        currentRx,
        currentTx,
        rxRate,
        txRate,
      })
    })

    console.log('[updateTrafficRateHistory] nextPoint:', nextPoint)

    setTrafficHistory((prevHistory) => {
      const next = [...prevHistory, nextPoint]
      console.log('[updateTrafficRateHistory] next trafficHistory:', next)
      return next.slice(-TRAFFIC_HISTORY_LIMIT)
    })

    lastTrafficRef.current = {
      timestamp: now,
      interfaces: currentMap,
    }
  }

  const fetchDashboard = async () => {
    try {
      setLoading(true)
      setError('')

      const res = await fetch(`${API_BASE}/api/opnsense/dashboard`)
      const data = await res.json()

      console.log('dashboard 응답:', data)

      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '대시보드 조회 실패'))
      }

      setDashboard(data)
      updateTrafficRateHistory(data?.traffic)

      const warnings = [
        data?.status?.error ? `상태 정보 오류: ${data.status.error}` : '',
        data?.rules?.error ? `룰 정보 오류: ${data.rules.error}` : '',
        data?.system?.error ? `시스템 정보 오류: ${data.system.error}` : '',
        data?.memory?.error ? `메모리 정보 오류: ${data.memory.error}` : '',
        data?.disk?.error ? `디스크 정보 오류: ${data.disk.error}` : '',
        data?.traffic?.error ? `트래픽 정보 오류: ${data.traffic.error}` : '',
      ].filter(Boolean)

      if (warnings.length > 0) {
        warnings.forEach((msg) => addLog('WARN', msg))
      } else {
        addLog('INFO', '대시보드 갱신 완료')
      }
    } catch (err) {
      const msg = err.message || '대시보드를 불러오지 못했습니다.'
      setError(msg)
      addLog('ERROR', msg)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchDashboard()
  }, [])

  useEffect(() => {
    if (!autoRefresh) return

    const interval = setInterval(() => {
      fetchDashboard()
    }, 5000)

    return () => clearInterval(interval)
  }, [autoRefresh])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
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

    try {
      setSubmitting(true)
      setError('')

      const res = await fetch(`${API_BASE}/api/opnsense/rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '룰 추가 실패'))
      }

      addLog('INFO', `룰 추가 성공: ${form.description || '설명 없음'}`)
      alert('✅ 룰이 추가되었습니다.')

      resetForm()
      await fetchDashboard()
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
    const ok = window.confirm(
      `정말 삭제할까요?\n\n${description || '설명 없음'}`,
    )
    if (!ok) return

    try {
      setError('')

      const res = await fetch(`${API_BASE}/api/opnsense/rules/${uuid}`, {
        method: 'DELETE',
      })

      const data = await res.json().catch(() => ({}))

      if (!res.ok) {
        throw new Error(parseErrorMessage(data, '룰 삭제 실패'))
      }

      addLog('WARN', `룰 삭제 성공: ${description || uuid}`)
      alert('🗑️ 룰이 삭제되었습니다.')
      await fetchDashboard()
    } catch (err) {
      const msg = err.message || '룰 삭제 중 오류가 발생했습니다.'
      setError(msg)
      addLog('ERROR', `룰 삭제 실패: ${msg}`)
      alert(`❌ ${msg}`)
    }
  }

  const product = dashboard?.product || dashboard?.status?.product || null
  const status = dashboard?.status || null
  const rules = Array.isArray(dashboard?.rules?.rows)
    ? dashboard.rules.rows
    : []
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
          <button onClick={fetchDashboard} disabled={loading}>
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
        </div>

        {error && <div className="error card">에러: {error}</div>}

        {currentPage === 'dashboard' && (
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
          />
        )}

        {currentPage === 'rules' && (
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
          />
        )}

        {currentPage === 'logs' && <LogsPage logs={logs} setLogs={setLogs} />}
      </main>
    </div>
  )
}

export default App
