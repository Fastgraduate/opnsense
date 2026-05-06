import { useEffect, useState } from 'react'
import './App.css'

import Sidebar from './components/layout/Sidebar'
import DashboardPage from './pages/DashboardPage'
import RulesPage from './pages/RulesPage'
import LogsPage from './pages/LogsPage'

const API_BASE = 'http://127.0.0.1:8000'

function App() {
  const [currentPage, setCurrentPage] = useState('dashboard')
  const [dashboard, setDashboard] = useState(null)

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

  const fetchDashboard = async () => {
    try {
      setLoading(true)
      setError('')

      const res = await fetch(`${API_BASE}/api/opnsense/dashboard`)
      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.message || '대시보드 조회 실패')
      }

      setDashboard(data)
      addLog('INFO', '대시보드 갱신 완료')
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
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(form),
      })

      const data = await res.json()

      if (!res.ok) {
        throw new Error(data.message || '룰 추가 실패')
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
        throw new Error(data.message || '룰 삭제 실패')
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

  const product = dashboard?.status?.product || null
  const status = dashboard?.status || null
  const rules = dashboard?.rules?.rows || []
  const system = dashboard?.system || null
  const interfaces = dashboard?.interfaces || null
  const services = dashboard?.services || null
  const traffic = dashboard?.traffic || null
  const aliases = Array.isArray(dashboard?.aliases) ? dashboard.aliases : []

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
            rules={rules}
            system={system}
            interfaces={interfaces}
            services={services}
            traffic={traffic}
            autoRefresh={autoRefresh}
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
