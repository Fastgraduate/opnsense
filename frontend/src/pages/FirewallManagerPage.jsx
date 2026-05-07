import { useMemo, useState } from 'react'

const EMPTY_FORM = {
  name: '',
  host: '',
  api_key: '',
  api_secret: '',
  verify_ssl: false,
  log_index: 'logs-suricata.eve-*',
  description: '',
  elastic_url: '',
  elastic_api_key: '',
  elastic_username: '',
  elastic_password: '',
  elastic_verify_ssl: false,
}

function FirewallManagerPage({
  firewalls,
  selectedFirewallId,
  setSelectedFirewallId,
  onCreateFirewall,
  onUpdateFirewall,
  onDeleteFirewall,
}) {
  const [form, setForm] = useState(EMPTY_FORM)
  const [editForm, setEditForm] = useState(null)
  const [saving, setSaving] = useState(false)
  const [updating, setUpdating] = useState(false)

  const selectedFirewall = useMemo(
    () => firewalls.find((fw) => fw.id === selectedFirewallId) || null,
    [firewalls, selectedFirewallId],
  )

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  const handleEditChange = (e) => {
    const { name, value, type, checked } = e.target
    setEditForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
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

  const startEdit = (fw) => {
    setEditForm({
      id: fw.id,
      name: fw.name || '',
      host: fw.host || '',
      api_key: '',
      api_secret: '',
      verify_ssl: !!fw.verify_ssl,
      log_index: fw.log_index || 'logs-suricata.eve-*',
      description: fw.description || '',
      elastic_url: fw.elastic?.url || '',
      elastic_api_key: '',
      elastic_username: '',
      elastic_password: '',
      elastic_verify_ssl: !!fw.elastic?.verify_ssl,
    })
  }

  const cancelEdit = () => {
    setEditForm(null)
  }

  const handleUpdate = async (e) => {
    e.preventDefault()
    if (!editForm?.id) return

    setUpdating(true)
    try {
      const payload = {
        name: editForm.name,
        host: editForm.host,
        verify_ssl: editForm.verify_ssl,
        log_index: editForm.log_index,
        description: editForm.description,
        elastic_url: editForm.elastic_url,
        elastic_verify_ssl: editForm.elastic_verify_ssl,
      }

      if (editForm.api_key.trim()) {
        payload.api_key = editForm.api_key.trim()
      }
      if (editForm.api_secret.trim()) {
        payload.api_secret = editForm.api_secret.trim()
      }
      if (editForm.elastic_api_key.trim()) {
        payload.elastic_api_key = editForm.elastic_api_key.trim()
      }
      if (editForm.elastic_username.trim()) {
        payload.elastic_username = editForm.elastic_username.trim()
      }
      if (editForm.elastic_password.trim()) {
        payload.elastic_password = editForm.elastic_password.trim()
      }

      await onUpdateFirewall(editForm.id, payload)
      setEditForm(null)
    } finally {
      setUpdating(false)
    }
  }

  return (
    <div className="page main-grid">
      <div className="card form-card">
        <div className="card-header-row">
          <h3>{editForm ? '방화벽 수정' : '방화벽 등록'}</h3>
        </div>

        {!editForm ? (
          <form onSubmit={handleSubmit}>
            <div className="form-grid">
              <div>
                <label>이름</label>
                <input
                  name="name"
                  value={form.name}
                  onChange={handleChange}
                  required
                />
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
                <input
                  name="api_key"
                  value={form.api_key}
                  onChange={handleChange}
                  required
                />
              </div>

              <div>
                <label>API Secret</label>
                <input
                  name="api_secret"
                  value={form.api_secret}
                  onChange={handleChange}
                  required
                />
              </div>

              <div>
                <label>로그 인덱스</label>
                <input
                  name="log_index"
                  value={form.log_index}
                  onChange={handleChange}
                />
              </div>

              <div>
                <label>설명</label>
                <input
                  name="description"
                  value={form.description}
                  onChange={handleChange}
                />
              </div>

              <div>
                <label>Elastic URL</label>
                <input
                  name="elastic_url"
                  value={form.elastic_url}
                  onChange={handleChange}
                  placeholder="http://localhost:9200"
                />
              </div>

              <div>
                <label>Elastic API Key</label>
                <input
                  name="elastic_api_key"
                  value={form.elastic_api_key}
                  onChange={handleChange}
                  placeholder="있으면 사용자/비밀번호 대신 사용"
                />
              </div>

              <div>
                <label>Elastic Username</label>
                <input
                  name="elastic_username"
                  value={form.elastic_username}
                  onChange={handleChange}
                />
              </div>

              <div>
                <label>Elastic Password</label>
                <input
                  name="elastic_password"
                  value={form.elastic_password}
                  onChange={handleChange}
                />
              </div>
            </div>

            <div className="form-actions" style={{ marginTop: '12px' }}>
              <label className="checkbox-inline">
                <input
                  type="checkbox"
                  name="verify_ssl"
                  checked={form.verify_ssl}
                  onChange={handleChange}
                />
                OPNsense SSL 검증 사용
              </label>

              <label className="checkbox-inline">
                <input
                  type="checkbox"
                  name="elastic_verify_ssl"
                  checked={form.elastic_verify_ssl}
                  onChange={handleChange}
                />
                Elastic SSL 검증 사용
              </label>
            </div>

            <div className="form-actions">
              <button disabled={saving}>
                {saving ? '저장 중...' : '방화벽 등록'}
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleUpdate}>
            <div className="form-grid">
              <div>
                <label>이름</label>
                <input
                  name="name"
                  value={editForm.name}
                  onChange={handleEditChange}
                  required
                />
              </div>

              <div>
                <label>Host</label>
                <input
                  name="host"
                  value={editForm.host}
                  onChange={handleEditChange}
                  required
                />
              </div>

              <div>
                <label>새 API Key</label>
                <input
                  name="api_key"
                  value={editForm.api_key}
                  onChange={handleEditChange}
                  placeholder="변경할 때만 입력"
                />
              </div>

              <div>
                <label>새 API Secret</label>
                <input
                  name="api_secret"
                  value={editForm.api_secret}
                  onChange={handleEditChange}
                  placeholder="변경할 때만 입력"
                />
              </div>

              <div>
                <label>로그 인덱스</label>
                <input
                  name="log_index"
                  value={editForm.log_index}
                  onChange={handleEditChange}
                />
              </div>

              <div>
                <label>설명</label>
                <input
                  name="description"
                  value={editForm.description}
                  onChange={handleEditChange}
                />
              </div>

              <div>
                <label>Elastic URL</label>
                <input
                  name="elastic_url"
                  value={editForm.elastic_url}
                  onChange={handleEditChange}
                  placeholder="http://localhost:9200"
                />
              </div>

              <div>
                <label>새 Elastic API Key</label>
                <input
                  name="elastic_api_key"
                  value={editForm.elastic_api_key}
                  onChange={handleEditChange}
                  placeholder="변경할 때만 입력"
                />
              </div>

              <div>
                <label>새 Elastic Username</label>
                <input
                  name="elastic_username"
                  value={editForm.elastic_username}
                  onChange={handleEditChange}
                  placeholder="변경할 때만 입력"
                />
              </div>

              <div>
                <label>새 Elastic Password</label>
                <input
                  name="elastic_password"
                  value={editForm.elastic_password}
                  onChange={handleEditChange}
                  placeholder="변경할 때만 입력"
                />
              </div>
            </div>

            <div className="form-actions" style={{ marginTop: '12px' }}>
              <label className="checkbox-inline">
                <input
                  type="checkbox"
                  name="verify_ssl"
                  checked={editForm.verify_ssl}
                  onChange={handleEditChange}
                />
                OPNsense SSL 검증 사용
              </label>

              <label className="checkbox-inline">
                <input
                  type="checkbox"
                  name="elastic_verify_ssl"
                  checked={editForm.elastic_verify_ssl}
                  onChange={handleEditChange}
                />
                Elastic SSL 검증 사용
              </label>
            </div>

            <div className="form-actions">
              <button disabled={updating}>
                {updating ? '수정 중...' : '수정 저장'}
              </button>
              <button type="button" className="delete-btn" onClick={cancelEdit}>
                취소
              </button>
            </div>
          </form>
        )}
      </div>

      <div className="card rules-card">
        <div className="card-header-row">
          <h3>등록된 방화벽</h3>
        </div>

        {selectedFirewall ? (
          <div style={{ marginBottom: '12px', fontWeight: 700 }}>
            현재 선택: {selectedFirewall.name}
          </div>
        ) : null}

        <div className="log-list">
          {firewalls.length === 0 ? (
            <p>등록된 방화벽이 없습니다.</p>
          ) : (
            firewalls.map((fw) => (
              <div key={fw.id} className="log-item">
                <div className="log-content">
                  <div className="log-message">{fw.name}</div>
                  <div className="log-time">{fw.host}</div>
                  <div className="log-time">로그 인덱스: {fw.log_index}</div>
                  <div className="log-time">
                    OPNsense SSL 검증: {fw.verify_ssl ? '사용' : '미사용'}
                  </div>
                  <div className="log-time">
                    Elastic:{' '}
                    {fw.elastic?.enabled
                      ? fw.elastic.url || '기본값 사용'
                      : '미설정'}
                  </div>
                  <div className="log-time">
                    Elastic SSL 검증:{' '}
                    {fw.elastic?.verify_ssl ? '사용' : '미사용'}
                  </div>
                </div>

                <div className="form-actions">
                  <button onClick={() => setSelectedFirewallId(fw.id)}>
                    {selectedFirewallId === fw.id ? '선택됨' : '선택'}
                  </button>
                  <button onClick={() => startEdit(fw)}>수정</button>
                  <button
                    className="delete-btn"
                    onClick={() => onDeleteFirewall(fw.id)}
                  >
                    삭제
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

export default FirewallManagerPage
