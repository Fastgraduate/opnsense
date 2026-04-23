import { useState } from 'react'

const EMPTY_FORM = {
  name: '', host: '', api_key: '', api_secret: '', verify_ssl: false, log_index: 'logs-suricata.eve-*', description: ''
}

function FirewallManagerPage({ firewalls, selectedFirewallId, setSelectedFirewallId, onCreateFirewall, onDeleteFirewall }) {
  const [form, setForm] = useState(EMPTY_FORM)
  const [saving, setSaving] = useState(false)

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({ ...prev, [name]: type === 'checkbox' ? checked : value }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSaving(true)
    try {
      await onCreateFirewall(form)
      setForm(EMPTY_FORM)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="page main-grid">
      <div className="card form-card">
        <div className="card-header-row"><h3>방화벽 등록</h3></div>
        <form onSubmit={handleSubmit}>
          <div className="form-grid">
            <div><label>이름</label><input name="name" value={form.name} onChange={handleChange} required /></div>
            <div><label>Host</label><input name="host" value={form.host} onChange={handleChange} placeholder="https://192.168.44.141" required /></div>
            <div><label>API Key</label><input name="api_key" value={form.api_key} onChange={handleChange} required /></div>
            <div><label>API Secret</label><input name="api_secret" value={form.api_secret} onChange={handleChange} required /></div>
            <div><label>로그 인덱스</label><input name="log_index" value={form.log_index} onChange={handleChange} /></div>
            <div><label>설명</label><input name="description" value={form.description} onChange={handleChange} /></div>
          </div>
          <label className="checkbox-inline" style={{ marginTop: '12px' }}>
            <input type="checkbox" name="verify_ssl" checked={form.verify_ssl} onChange={handleChange} /> SSL 검증 사용
          </label>
          <div className="form-actions"><button disabled={saving}>{saving ? '저장 중...' : '방화벽 등록'}</button></div>
        </form>
      </div>
      <div className="card rules-card">
        <div className="card-header-row"><h3>등록된 방화벽</h3></div>
        <div className="log-list">
          {firewalls.length === 0 ? <p>등록된 방화벽이 없습니다.</p> : firewalls.map((fw) => (
            <div key={fw.id} className="log-item">
              <div className="log-content">
                <div className="log-message">{fw.name}</div>
                <div className="log-time">{fw.host}</div>
                <div className="log-time">로그 인덱스: {fw.log_index}</div>
              </div>
              <div className="form-actions">
                <button onClick={() => setSelectedFirewallId(fw.id)}>{selectedFirewallId === fw.id ? '선택됨' : '선택'}</button>
                <button className="delete-btn" onClick={() => onDeleteFirewall(fw.id)}>삭제</button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default FirewallManagerPage
