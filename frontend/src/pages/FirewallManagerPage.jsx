
import { useState } from 'react'

function FirewallManagerPage({
  items = [],
  selectedFirewallId,
  onSelect,
  onCreate,
  onDelete,
  onTest,
}) {
  const [form, setForm] = useState({
    name: '',
    host: '',
    apiKey: '',
    apiSecret: '',
    verifySsl: false,
    timeout: 20,
  })
  const [loadingId, setLoadingId] = useState(null)
  const [creating, setCreating] = useState(false)

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    try {
      setCreating(true)
      await onCreate({
        ...form,
        timeout: Number(form.timeout) || 20,
      })
      setForm({
        name: '',
        host: '',
        apiKey: '',
        apiSecret: '',
        verifySsl: false,
        timeout: 20,
      })
      alert('✅ 방화벽이 등록되었습니다.')
    } catch (err) {
      alert(`❌ ${err.message}`)
    } finally {
      setCreating(false)
    }
  }

  const handleTest = async (id) => {
    try {
      setLoadingId(id)
      const result = await onTest(id)
      alert(`✅ 연결 성공\n제품: ${result?.product?.product_name || '확인됨'}`)
    } catch (err) {
      alert(`❌ 연결 실패\n${err.message}`)
    } finally {
      setLoadingId(null)
    }
  }

  const handleDelete = async (id, name) => {
    const ok = window.confirm(`정말 삭제할까요?\n\n${name}`)
    if (!ok) return
    try {
      setLoadingId(id)
      await onDelete(id)
      alert('🗑️ 삭제되었습니다.')
    } catch (err) {
      alert(`❌ 삭제 실패\n${err.message}`)
    } finally {
      setLoadingId(null)
    }
  }

  return (
    <div className="main-grid">
      <div className="card form-card">
        <div className="card-header-row">
          <h3>방화벽 등록</h3>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            <div>
              <label>방화벽 이름</label>
              <input name="name" value={form.name} onChange={handleChange} required />
            </div>
            <div>
              <label>Host</label>
              <input
                name="host"
                value={form.host}
                onChange={handleChange}
                placeholder="https://192.168.44.141"
                required
              />
            </div>
            <div>
              <label>API Key</label>
              <input name="apiKey" value={form.apiKey} onChange={handleChange} required />
            </div>
            <div>
              <label>API Secret</label>
              <input name="apiSecret" value={form.apiSecret} onChange={handleChange} required />
            </div>
            <div>
              <label>Timeout(초)</label>
              <input name="timeout" type="number" min="3" max="60" value={form.timeout} onChange={handleChange} />
            </div>
            <div className="checkbox-inline checkbox-row">
              <input
                id="verifySsl"
                name="verifySsl"
                type="checkbox"
                checked={form.verifySsl}
                onChange={handleChange}
              />
              <label htmlFor="verifySsl">SSL 검증 사용</label>
            </div>
          </div>

          <div className="form-actions">
            <button type="submit" disabled={creating}>{creating ? '등록 중...' : '방화벽 등록'}</button>
          </div>
        </form>
      </div>

      <div className="card rules-card">
        <div className="section-header">
          <h3>등록된 방화벽</h3>
          <span className="rule-count">{items.length}개</span>
        </div>

        {items.length === 0 ? (
          <p className="empty-text">아직 등록된 방화벽이 없습니다.</p>
        ) : (
          <div className="firewall-list">
            {items.map((item) => (
              <div key={item.id} className={`firewall-item ${selectedFirewallId === item.id ? 'selected' : ''}`}>
                <div className="firewall-item__main">
                  <div className="firewall-item__title">{item.name}</div>
                  <div className="firewall-item__host">{item.host}</div>
                  <div className="firewall-item__meta">
                    <span>Key: {item.apiKeyMasked}</span>
                    <span>Secret: {item.apiSecretMasked}</span>
                    <span>SSL: {item.verifySsl ? 'ON' : 'OFF'}</span>
                    <span>Timeout: {item.timeout}s</span>
                  </div>
                </div>

                <div className="firewall-item__actions">
                  <button onClick={() => onSelect(item.id)} disabled={selectedFirewallId === item.id}>
                    {selectedFirewallId === item.id ? '선택됨' : '선택'}
                  </button>
                  <button onClick={() => handleTest(item.id)} disabled={loadingId === item.id}>
                    테스트
                  </button>
                  <button className="delete-btn" onClick={() => handleDelete(item.id, item.name)} disabled={loadingId === item.id}>
                    삭제
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default FirewallManagerPage
