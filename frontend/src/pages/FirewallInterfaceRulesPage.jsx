import { useEffect, useMemo, useState } from 'react'

const DEFAULT_RULE_FORM = {
  uuid: '',
  interface: 'lan',
  description: '',
  action: 'pass',
  direction: 'in',
  protocol: 'TCP',
  sourceNet: 'any',
  sourcePort: '',
  destinationNet: 'any',
  destinationPort: '',
  log: false,
  enabled: '1',
  quick: '1',
}

const ACTION_LABELS = {
  pass: 'PASS',
  block: 'BLOCK',
  reject: 'REJECT',
  match: 'MATCH',
}

const KIND_LABELS = {
  group: '그룹',
  automatic: '자동 생성 규칙',
  legacy: '기존 GUI 룰',
  automation: '자동화 규칙',
  managed: '관리 룰',
  unknown: '기타',
}

const directionLabel = (value) => {
  const text = String(value || '').toLowerCase()

  if (text === 'in') return '수신'
  if (text === 'out') return '송신'

  return value || '-'
}

const toDisplayText = (value, fallback = '-') => {
  if (value == null || value === '') return fallback

  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value)
  }

  if (Array.isArray(value)) {
    const text = value.map((item) => toDisplayText(item, '')).filter(Boolean).join(', ')
    return text || fallback
  }

  if (typeof value === 'object') {
    if (value.name) return String(value.name)
    if (value.value) return toDisplayText(value.value, fallback)
    return JSON.stringify(value)
  }

  return fallback
}

function RuleSection({
  title,
  rows,
  defaultOpen = false,
  readonlySection = false,
  openEditForm,
  handleDelete,
}) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <>
      <tr className="if-rule-generated-group">
        <td colSpan="10">
          <button
            type="button"
            className="if-rule-generated-toggle"
            onClick={() => setOpen((prev) => !prev)}
          >
            <span className={`if-rule-generated-arrow ${open ? 'open' : ''}`}>
              ▶
            </span>
            <span className="if-rule-folder-icon">▱</span>
            <span>{title}</span>
            <span className="if-rule-generated-count">{rows.length}개</span>
          </button>
        </td>
      </tr>

      {open
        ? rows.map((rule, index) => {
            if (rule.kind === 'group') {
              return (
                <tr key={`${rule.uuid || index}-group`} className="if-rule-legacy-subgroup">
                  <td colSpan="10">{rule.description || rule.rawText}</td>
                </tr>
              )
            }

            return (
              <tr
                key={`${rule.kind}-${rule.uuid || index}`}
                className={`${String(rule.enabled) === '0' ? 'disabled' : ''} ${
                  rule.readonly || readonlySection ? 'generated' : ''
                }`}
              >
                <td>
                  <span
                    className={`if-rule-state ${
                      String(rule.enabled) === '0' ? 'off' : 'on'
                    }`}
                  />
                </td>

                <td>
                  <span className={`if-rule-kind ${rule.kind || 'managed'}`}>
                    {KIND_LABELS[rule.kind] || rule.kind || '관리 룰'}
                  </span>
                </td>

                <td>{toDisplayText(rule.interface)}</td>
                <td>{directionLabel(rule.direction)}</td>

                <td>
                  <span className={`if-rule-action ${rule.action}`}>
                    {ACTION_LABELS[rule.action] || rule.action || '-'}
                  </span>
                </td>

                <td>{toDisplayText(rule.protocol)}</td>

                <td>
                  {toDisplayText(rule.sourceNet)}
                  {rule.sourcePort ? `:${rule.sourcePort}` : ''}
                </td>

                <td>
                  {toDisplayText(rule.destinationNet)}
                  {rule.destinationPort ? `:${rule.destinationPort}` : ''}
                </td>

                <td className="if-rule-desc" title={rule.rawText || rule.description}>
                  {toDisplayText(rule.description)}
                </td>

                <td>
                  {rule.readonly || readonlySection ? (
                    <span className="if-rule-readonly">조회 전용</span>
                  ) : (
                    <div className="if-rule-row-actions">
                      <button type="button" onClick={() => openEditForm(rule)}>
                        수정
                      </button>
                      <button
                        type="button"
                        className="danger"
                        onClick={() => handleDelete(rule)}
                      >
                        삭제
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            )
          })
        : null}
    </>
  )
}

function FirewallInterfaceRulesPage({
  selectedFirewall,
  fetchFirewallInterfaces,
  fetchInterfaceRules,
  fetchLegacyInterfaceRules,
  createInterfaceRule,
  updateInterfaceRule,
  deleteInterfaceRule,
  applyInterfaceRules,
}) {
  const [interfaces, setInterfaces] = useState([])
  const [rules, setRules] = useState([])
  const [legacyRules, setLegacyRules] = useState([])
  const [selectedInterface, setSelectedInterface] = useState('all')
  const [form, setForm] = useState(DEFAULT_RULE_FORM)
  const [editingUuid, setEditingUuid] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [loading, setLoading] = useState(false)
  const [legacyLoading, setLegacyLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [legacyError, setLegacyError] = useState('')
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null)

  const selectedName = selectedFirewall?.name || '없음'

  const interfaceTabs = useMemo(() => {
    const normalized = interfaces.map((item) => ({
      key: item.key,
      name: item.name || item.key?.toUpperCase(),
      device: item.device,
    }))

    return [{ key: 'all', name: '전체', device: '-' }, ...normalized]
  }, [interfaces])

  const filteredApiRules = useMemo(() => {
    if (selectedInterface === 'all') return rules

    return rules.filter((rule) => {
      const value = String(rule.interface || '').toLowerCase()
      return value === selectedInterface || value.split(',').includes(selectedInterface)
    })
  }, [rules, selectedInterface])

  const groupedRules = useMemo(() => {
    const legacyAutomatic = []
    const legacyNormal = []
    const automation = []
    const managed = []
    const unknown = []

    legacyRules.forEach((rule) => {
      if (rule.kind === 'automatic' || rule.kind === 'group') {
        legacyAutomatic.push(rule)
      } else {
        legacyNormal.push(rule)
      }
    })

    filteredApiRules.forEach((rule) => {
      if (rule.kind === 'automation') {
        automation.push(rule)
      } else if (rule.kind === 'managed' || !rule.kind) {
        managed.push({ ...rule, kind: rule.kind || 'managed' })
      } else {
        unknown.push(rule)
      }
    })

    return {
      legacyAutomatic,
      legacyNormal,
      automation,
      managed,
      unknown,
    }
  }, [legacyRules, filteredApiRules])

  const totalVisibleCount =
    groupedRules.legacyAutomatic.length +
    groupedRules.legacyNormal.length +
    groupedRules.automation.length +
    groupedRules.managed.length +
    groupedRules.unknown.length

  const loadInterfaces = async () => {
    if (!selectedFirewall) {
      setInterfaces([])
      return
    }

    const data = await fetchFirewallInterfaces()
    const list = Array.isArray(data?.interfaces) ? data.interfaces : []

    setInterfaces(list)

    if (list.length > 0 && form.interface === 'lan') {
      setForm((prev) => ({
        ...prev,
        interface: list.find((item) => item.key === 'lan')?.key || list[0].key,
      }))
    }
  }

  const loadApiRules = async () => {
    if (!selectedFirewall) {
      setRules([])
      setError('방화벽을 먼저 선택하세요.')
      return
    }

    try {
      setLoading(true)
      setError('')

      const data = await fetchInterfaceRules()
      const list = Array.isArray(data?.rows) ? data.rows : []

      setRules(list)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setRules([])
      setError(err.message || '인터페이스별 API 룰 목록을 불러오지 못했습니다.')
    } finally {
      setLoading(false)
    }
  }

  const loadLegacyRules = async () => {
    if (!selectedFirewall || selectedInterface === 'all' || !fetchLegacyInterfaceRules) {
      setLegacyRules([])
      return
    }

    try {
      setLegacyLoading(true)
      setLegacyError('')

      const data = await fetchLegacyInterfaceRules(selectedInterface)
      const list = Array.isArray(data?.rows) ? data.rows : []

      setLegacyRules(list)
      setLastUpdatedAt(new Date())
    } catch (err) {
      setLegacyRules([])
      setLegacyError(err.message || 'OPNsense WebGUI 룰을 불러오지 못했습니다.')
    } finally {
      setLegacyLoading(false)
    }
  }

  const loadAllRules = async () => {
    await Promise.allSettled([loadApiRules(), loadLegacyRules()])
  }

  useEffect(() => {
    loadInterfaces().catch((err) =>
      setError(err.message || '인터페이스 목록 조회 실패'),
    )
  }, [selectedFirewall])

  useEffect(() => {
    loadAllRules()
  }, [selectedFirewall, selectedInterface])

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target

    setForm((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }))
  }

  const resetForm = () => {
    setForm({
      ...DEFAULT_RULE_FORM,
      interface:
        selectedInterface !== 'all'
          ? selectedInterface
          : interfaces.find((item) => item.key === 'lan')?.key ||
            interfaces[0]?.key ||
            'lan',
    })
    setEditingUuid('')
    setShowForm(false)
  }

  const openCreateForm = () => {
    setForm({
      ...DEFAULT_RULE_FORM,
      interface:
        selectedInterface !== 'all'
          ? selectedInterface
          : interfaces.find((item) => item.key === 'lan')?.key ||
            interfaces[0]?.key ||
            'lan',
    })
    setEditingUuid('')
    setShowForm(true)
  }

  const openEditForm = (rule) => {
    if (rule.readonly) return

    setForm({
      uuid: rule.uuid || '',
      interface: rule.interface || 'lan',
      description: rule.description || '',
      action: rule.action || 'pass',
      direction: rule.direction || 'in',
      protocol: rule.protocol || 'TCP',
      sourceNet: rule.sourceNet || 'any',
      sourcePort: rule.sourcePort || '',
      destinationNet: rule.destinationNet || 'any',
      destinationPort: rule.destinationPort || '',
      log: !!rule.log,
      enabled: rule.enabled ?? '1',
      quick: rule.quick ?? '1',
    })

    setEditingUuid(rule.uuid || '')
    setShowForm(true)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    try {
      setSubmitting(true)
      setError('')

      if (editingUuid) {
        await updateInterfaceRule(editingUuid, form)
      } else {
        await createInterfaceRule(form)
      }

      await loadAllRules()
      resetForm()
    } catch (err) {
      setError(err.message || '룰 저장 실패')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (rule) => {
    if (!rule.uuid || rule.readonly) return

    if (!window.confirm(`정말 삭제할까요?\n\n${rule.description || rule.uuid}`)) {
      return
    }

    try {
      setError('')
      await deleteInterfaceRule(rule.uuid)
      await loadAllRules()
    } catch (err) {
      setError(err.message || '룰 삭제 실패')
    }
  }

  const handleApply = async () => {
    try {
      setSubmitting(true)
      setError('')
      await applyInterfaceRules()
      await loadAllRules()
    } catch (err) {
      setError(err.message || '룰 적용 실패')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="if-rule-page">
      <section className="if-rule-header">
        <div>
          <p className="if-rule-eyebrow">OPNsense Interface Rules</p>
          <h2>인터페이스별 방화벽 룰 관리</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className="if-rule-header-actions">
          <button type="button" onClick={loadAllRules} disabled={loading || legacyLoading}>
            {loading || legacyLoading ? '갱신 중...' : '새로고침'}
          </button>

          <button type="button" className="primary" onClick={openCreateForm}>
            룰 추가
          </button>

          <button
            type="button"
            className="dark"
            onClick={handleApply}
            disabled={submitting}
          >
            변경사항 적용
          </button>
        </div>
      </section>

      {error ? <div className="if-rule-error">에러: {error}</div> : null}
      {legacyError ? <div className="if-rule-error">WebGUI 룰 조회 오류: {legacyError}</div> : null}

      <section className="if-rule-tabs-card">
        <div className="if-rule-tabs">
          {interfaceTabs.map((item) => (
            <button
              key={item.key}
              type="button"
              className={selectedInterface === item.key ? 'active' : ''}
              onClick={() => {
                setSelectedInterface(item.key)
                setShowForm(false)
                setEditingUuid('')
              }}
            >
              <strong>{item.name}</strong>
              <span>
                {item.key === 'all'
                  ? `${rules.length} rules`
                  : item.device || item.key}
              </span>
            </button>
          ))}
        </div>
      </section>

      {showForm ? (
        <section className="if-rule-form-card">
          <div className="if-rule-section-title">
            <div>
              <p>{editingUuid ? 'Edit Rule' : 'Add Rule'}</p>
              <h3>{editingUuid ? '룰 수정' : '새 룰 추가'}</h3>
            </div>

            <button type="button" onClick={resetForm}>
              닫기
            </button>
          </div>

          <form onSubmit={handleSubmit}>
            <div className="if-rule-form-grid">
              <label>
                <span>인터페이스</span>
                <select
                  name="interface"
                  value={form.interface}
                  onChange={handleChange}
                >
                  {interfaces.map((item) => (
                    <option key={item.key} value={item.key}>
                      {item.name} ({item.key})
                    </option>
                  ))}
                </select>
              </label>

              <label>
                <span>Action</span>
                <select name="action" value={form.action} onChange={handleChange}>
                  <option value="pass">pass</option>
                  <option value="block">block</option>
                  <option value="reject">reject</option>
                </select>
              </label>

              <label>
                <span>Direction</span>
                <select
                  name="direction"
                  value={form.direction}
                  onChange={handleChange}
                >
                  <option value="in">in</option>
                  <option value="out">out</option>
                </select>
              </label>

              <label>
                <span>Protocol</span>
                <select
                  name="protocol"
                  value={form.protocol}
                  onChange={handleChange}
                >
                  <option value="TCP">TCP</option>
                  <option value="UDP">UDP</option>
                  <option value="TCP/UDP">TCP/UDP</option>
                  <option value="ICMP">ICMP</option>
                  <option value="any">any</option>
                </select>
              </label>

              <label>
                <span>출발지</span>
                <input
                  name="sourceNet"
                  value={form.sourceNet}
                  onChange={handleChange}
                  placeholder="any, LAN net, 192.168.1.0/24"
                />
              </label>

              <label>
                <span>출발지 포트</span>
                <input
                  name="sourcePort"
                  value={form.sourcePort}
                  onChange={handleChange}
                  placeholder="비워두면 any"
                />
              </label>

              <label>
                <span>목적지</span>
                <input
                  name="destinationNet"
                  value={form.destinationNet}
                  onChange={handleChange}
                  placeholder="any, WAN address, 8.8.8.8"
                />
              </label>

              <label>
                <span>목적지 포트</span>
                <input
                  name="destinationPort"
                  value={form.destinationPort}
                  onChange={handleChange}
                  placeholder="80, 443, 53"
                />
              </label>

              <label className="wide">
                <span>설명</span>
                <input
                  name="description"
                  value={form.description}
                  onChange={handleChange}
                  placeholder="룰 설명"
                />
              </label>
            </div>

            <div className="if-rule-check-row">
              <label className="if-rule-checkbox-label">
                <input
                  type="checkbox"
                  name="log"
                  checked={form.log}
                  onChange={handleChange}
                />
                <span>로그 남기기</span>
              </label>

              <label className="if-rule-checkbox-label">
                <input
                  type="checkbox"
                  name="enabled"
                  checked={String(form.enabled) === '1'}
                  onChange={(e) =>
                    setForm((prev) => ({
                      ...prev,
                      enabled: e.target.checked ? '1' : '0',
                    }))
                  }
                />
                <span>활성화</span>
              </label>
            </div>

            <div className="if-rule-form-actions">
              <button type="submit" className="primary" disabled={submitting}>
                {submitting ? '저장 중...' : editingUuid ? '수정 저장' : '룰 추가'}
              </button>

              <button type="button" onClick={resetForm}>
                취소
              </button>
            </div>
          </form>
        </section>
      ) : null}

      <section className="if-rule-table-card">
        <div className="if-rule-section-title">
          <div>
            <p>Rules</p>
            <h3>
              {selectedInterface === 'all'
                ? '전체 룰'
                : `${
                    interfaceTabs.find((item) => item.key === selectedInterface)
                      ?.name || selectedInterface
                  } 룰`}
            </h3>
          </div>

          <span className="if-rule-count">
            {totalVisibleCount}개
            {lastUpdatedAt ? ` · ${lastUpdatedAt.toLocaleTimeString()} 갱신` : ''}
          </span>
        </div>

        {selectedInterface === 'all' ? (
          <div className="if-rule-notice">
            자동 생성 규칙과 기존 GUI 룰은 인터페이스별 페이지 HTML에서 읽기 때문에
            LAN/WAN 같은 개별 인터페이스 탭에서 표시됩니다.
          </div>
        ) : null}

        <div className="if-rule-table-wrap">
          <table className="if-rule-table">
            <thead>
              <tr>
                <th>상태</th>
                <th>종류</th>
                <th>인터페이스</th>
                <th>방향</th>
                <th>Action</th>
                <th>프로토콜</th>
                <th>출발지</th>
                <th>목적지</th>
                <th>설명</th>
                <th>관리</th>
              </tr>
            </thead>

            <tbody>
              {totalVisibleCount === 0 ? (
                <tr>
                  <td colSpan="10" className="if-rule-empty">
                    표시할 룰이 없습니다.
                  </td>
                </tr>
              ) : (
                <>
                  {groupedRules.legacyAutomatic.length > 0 ? (
                    <RuleSection
                      title="자동 생성 / 시스템 규칙"
                      rows={groupedRules.legacyAutomatic}
                      defaultOpen={false}
                      readonlySection={true}
                      openEditForm={openEditForm}
                      handleDelete={handleDelete}
                    />
                  ) : null}

                  {groupedRules.legacyNormal.length > 0 ? (
                    <RuleSection
                      title="기존 GUI 룰"
                      rows={groupedRules.legacyNormal}
                      defaultOpen={false}
                      readonlySection={true}
                      openEditForm={openEditForm}
                      handleDelete={handleDelete}
                    />
                  ) : null}

                  {groupedRules.automation.length > 0 ? (
                    <RuleSection
                      title="자동화 규칙"
                      rows={groupedRules.automation}
                      defaultOpen={false}
                      openEditForm={openEditForm}
                      handleDelete={handleDelete}
                    />
                  ) : null}

                  {groupedRules.managed.length > 0 ? (
                    <RuleSection
                      title="관리 가능 룰"
                      rows={groupedRules.managed}
                      defaultOpen={true}
                      openEditForm={openEditForm}
                      handleDelete={handleDelete}
                    />
                  ) : null}

                  {groupedRules.unknown.length > 0 ? (
                    <RuleSection
                      title="기타 룰"
                      rows={groupedRules.unknown}
                      defaultOpen={false}
                      readonlySection={true}
                      openEditForm={openEditForm}
                      handleDelete={handleDelete}
                    />
                  ) : null}
                </>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

export default FirewallInterfaceRulesPage
