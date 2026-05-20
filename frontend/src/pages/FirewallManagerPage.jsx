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

  const activeForm = editForm || form
  const isEditMode = !!editForm

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

  const renderInput = ({
    label,
    name,
    placeholder,
    required = false,
    type = 'text',
    secret = false,
  }) => {
    const value = activeForm[name] ?? ''
    const onChange = isEditMode ? handleEditChange : handleChange

    return (
      <div className="firewall-input-field">
        <label htmlFor={name}>
          {label}
          {required ? <span className="required-dot">*</span> : null}
        </label>

        <input
          id={name}
          type={secret ? 'password' : type}
          name={name}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          required={required}
        />
      </div>
    )
  }

  const renderCheckbox = ({ name, label }) => {
    const checked = !!activeForm[name]
    const onChange = isEditMode ? handleEditChange : handleChange

    return (
      <label className="firewall-checkbox">
        <input
          type="checkbox"
          name={name}
          checked={checked}
          onChange={onChange}
        />
        <span>{label}</span>
      </label>
    )
  }

  const getElasticStatus = (fw) => {
    if (!fw.elastic?.enabled) return '미설정'
    return fw.elastic?.url || '기본값 사용'
  }

  return (
    <div className="firewall-manager-page">
      <section className="firewall-form-panel">
        <div className="firewall-panel-header">
          <div>
            <p className="firewall-eyebrow">
              {isEditMode ? 'Edit Firewall' : 'Register Firewall'}
            </p>
            <h2>{isEditMode ? '방화벽 수정' : '방화벽 등록'}</h2>
            <span>
              {isEditMode
                ? '기존 방화벽 연결 정보와 Elastic 로그 설정을 수정합니다.'
                : 'OPNsense API와 Elastic 로그 연동 정보를 등록합니다.'}
            </span>
          </div>

          {isEditMode ? (
            <div className="firewall-target-chip">ID: {editForm.id}</div>
          ) : (
            <div className="firewall-target-chip">신규 등록</div>
          )}
        </div>

        <form onSubmit={isEditMode ? handleUpdate : handleSubmit}>
          <div className="firewall-form-section">
            <div className="firewall-section-title">
              <h3>OPNsense 연결 정보</h3>
              <p>방화벽 API 접근을 위한 기본 정보를 입력합니다.</p>
            </div>

            <div className="firewall-form-grid">
              {renderInput({
                label: '이름',
                name: 'name',
                placeholder: '예: Main Firewall',
                required: true,
              })}

              {renderInput({
                label: 'Host',
                name: 'host',
                placeholder: 'https://192.168.44.141',
                required: true,
              })}

              {renderInput({
                label: isEditMode ? '새 API Key' : 'API Key',
                name: 'api_key',
                placeholder: isEditMode
                  ? '변경할 때만 입력'
                  : 'OPNsense API Key',
                required: !isEditMode,
                secret: true,
              })}

              {renderInput({
                label: isEditMode ? '새 API Secret' : 'API Secret',
                name: 'api_secret',
                placeholder: isEditMode
                  ? '변경할 때만 입력'
                  : 'OPNsense API Secret',
                required: !isEditMode,
                secret: true,
              })}

              {renderInput({
                label: '로그 인덱스',
                name: 'log_index',
                placeholder: 'logs-suricata.eve-*',
              })}

              {renderInput({
                label: '설명',
                name: 'description',
                placeholder: '관리용 설명을 입력하세요',
              })}
            </div>
          </div>

          <div className="firewall-form-section">
            <div className="firewall-section-title">
              <h3>Elastic 로그 연동</h3>
              <p>
                Suricata 이벤트 로그를 조회할 Elastic 연결 정보를 입력합니다.
              </p>
            </div>

            <div className="firewall-form-grid">
              {renderInput({
                label: 'Elastic URL',
                name: 'elastic_url',
                placeholder: 'https://192.168.0.46:9200',
              })}

              {renderInput({
                label: isEditMode ? '새 Elastic API Key' : 'Elastic API Key',
                name: 'elastic_api_key',
                placeholder: isEditMode
                  ? '변경할 때만 입력'
                  : '있으면 사용자/비밀번호 대신 사용',
                secret: true,
              })}

              {renderInput({
                label: isEditMode ? '새 Elastic Username' : 'Elastic Username',
                name: 'elastic_username',
                placeholder: isEditMode ? '변경할 때만 입력' : 'elastic',
              })}

              {renderInput({
                label: isEditMode ? '새 Elastic Password' : 'Elastic Password',
                name: 'elastic_password',
                placeholder: isEditMode ? '변경할 때만 입력' : '비밀번호',
                secret: true,
              })}
            </div>
          </div>

          <div className="firewall-option-box">
            <div>
              <h4>SSL 검증 옵션</h4>
              <p>자체 서명 인증서 환경이면 검증을 끄고 사용할 수 있습니다.</p>
            </div>

            <div className="firewall-checkbox-group">
              {renderCheckbox({
                name: 'verify_ssl',
                label: 'OPNsense SSL 검증 사용',
              })}

              {renderCheckbox({
                name: 'elastic_verify_ssl',
                label: 'Elastic SSL 검증 사용',
              })}
            </div>
          </div>

          <div className="firewall-form-actions">
            <button
              className="firewall-primary-btn"
              disabled={isEditMode ? updating : saving}
            >
              {isEditMode
                ? updating
                  ? '수정 중...'
                  : '수정 저장'
                : saving
                  ? '저장 중...'
                  : '방화벽 등록'}
            </button>

            {isEditMode ? (
              <button
                type="button"
                className="firewall-secondary-btn"
                onClick={cancelEdit}
              >
                취소
              </button>
            ) : (
              <button
                type="button"
                className="firewall-secondary-btn"
                onClick={() => setForm(EMPTY_FORM)}
              >
                초기화
              </button>
            )}
          </div>
        </form>
      </section>

      <section className="firewall-list-panel">
        <div className="firewall-panel-header">
          <div>
            <p className="firewall-eyebrow">Managed Firewalls</p>
            <h2>등록된 방화벽</h2>
            <span>
              현재 선택:{' '}
              {selectedFirewall ? selectedFirewall.name : '선택된 방화벽 없음'}
            </span>
          </div>

          <div className="firewall-target-chip">총 {firewalls.length}개</div>
        </div>

        <div className="firewall-card-list">
          {firewalls.length === 0 ? (
            <div className="firewall-empty-card">
              <h3>등록된 방화벽이 없습니다.</h3>
              <p>왼쪽 등록 폼에서 OPNsense 방화벽을 먼저 추가하세요.</p>
            </div>
          ) : (
            firewalls.map((fw) => {
              const selected = selectedFirewallId === fw.id

              return (
                <article
                  key={fw.id}
                  className={`firewall-item-card ${selected ? 'selected' : ''}`}
                >
                  <div className="firewall-item-main">
                    <div className="firewall-avatar">
                      {String(fw.name || 'F')
                        .charAt(0)
                        .toUpperCase()}
                    </div>

                    <div className="firewall-item-content">
                      <div className="firewall-item-title-row">
                        <h3>{fw.name}</h3>

                        {selected ? (
                          <span className="firewall-selected-badge">
                            선택됨
                          </span>
                        ) : (
                          <span className="firewall-id-badge">ID {fw.id}</span>
                        )}
                      </div>

                      <p className="firewall-host">{fw.host}</p>

                      <div className="firewall-meta-grid">
                        <div>
                          <span>로그 인덱스</span>
                          <strong>{fw.log_index || '-'}</strong>
                        </div>

                        <div>
                          <span>OPNsense SSL</span>
                          <strong>{fw.verify_ssl ? '사용' : '미사용'}</strong>
                        </div>

                        <div>
                          <span>Elastic</span>
                          <strong>{getElasticStatus(fw)}</strong>
                        </div>

                        <div>
                          <span>Elastic SSL</span>
                          <strong>
                            {fw.elastic?.verify_ssl ? '사용' : '미사용'}
                          </strong>
                        </div>
                      </div>

                      {fw.description ? (
                        <p className="firewall-description">{fw.description}</p>
                      ) : null}
                    </div>
                  </div>

                  <div className="firewall-item-actions">
                    <button
                      type="button"
                      className={`firewall-select-btn ${selected ? 'active' : ''}`}
                      onClick={() => setSelectedFirewallId(fw.id)}
                    >
                      {selected ? '선택됨' : '선택'}
                    </button>

                    <button
                      type="button"
                      className="firewall-edit-btn"
                      onClick={() => startEdit(fw)}
                    >
                      수정
                    </button>

                    <button
                      type="button"
                      className="firewall-delete-btn"
                      onClick={() => onDeleteFirewall(fw.id)}
                    >
                      삭제
                    </button>
                  </div>
                </article>
              )
            })
          )}
        </div>
      </section>
    </div>
  )
}

export default FirewallManagerPage
