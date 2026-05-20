function RulesPage({
  rules,
  form,
  setForm,
  showAdvanced,
  setShowAdvanced,
  submitting,
  handleChange,
  handleAddRule,
  handleDeleteRule,
  resetForm,
  selectedFirewall,
}) {
  const getActionClass = (action) => {
    const value = String(action || '').toLowerCase()

    if (value === 'pass') return 'pass'
    if (value === 'block') return 'block'
    if (value === 'reject') return 'reject'

    return 'default'
  }

  const renderActionBadge = (action) => {
    const value = action || '-'

    return (
      <span className={`rule-action-badge ${getActionClass(value)}`}>
        <span aria-hidden="true" />
        <strong>{value}</strong>
      </span>
    )
  }

  const renderInput = ({ label, name, placeholder, required = false }) => (
    <div className="rule-input-field">
      <label htmlFor={name}>
        {label}
        {required ? <span className="required-dot">*</span> : null}
      </label>

      <input
        id={name}
        name={name}
        value={form[name]}
        onChange={handleChange}
        placeholder={placeholder}
      />
    </div>
  )

  const renderSelect = ({ label, name, children, required = false }) => (
    <div className="rule-input-field">
      <label htmlFor={name}>
        {label}
        {required ? <span className="required-dot">*</span> : null}
      </label>

      <div className="rule-select-wrap">
        <select
          id={name}
          name={name}
          value={form[name]}
          onChange={handleChange}
        >
          {children}
        </select>

        <span className="rule-select-icon">
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path
              fillRule="evenodd"
              d="M10 3a1 1 0 01.707.293l3 3a1 1 0 01-1.414 1.414L10 5.414 7.707 7.707a1 1 0 01-1.414-1.414l3-3A1 1 0 0110 3zm-3.707 9.293a1 1 0 011.414 0L10 14.586l2.293-2.293a1 1 0 011.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z"
              clipRule="evenodd"
            />
          </svg>
        </span>
      </div>
    </div>
  )

  return (
    <div className="rules-page">
      <section className="rules-form-panel">
        <div className="rules-panel-header">
          <div>
            <p className="rules-eyebrow">Firewall Policy</p>
            <h2>룰 추가</h2>
          </div>

          <div className="rules-target-chip">
            대상: {selectedFirewall?.name || '-'}
          </div>
        </div>

        <form onSubmit={handleAddRule}>
          <div className="rules-form-grid">
            {renderInput({
              label: '설명',
              name: 'description',
              placeholder: '예: Allow web traffic',
              required: true,
            })}

            {renderSelect({
              label: 'Action',
              name: 'action',
              required: true,
              children: (
                <>
                  <option value="pass">pass</option>
                  <option value="block">block</option>
                  <option value="reject">reject</option>
                </>
              ),
            })}

            {renderInput({
              label: 'Interface',
              name: 'interface',
              placeholder: '예: lan, wan',
              required: true,
            })}

            {renderSelect({
              label: 'Direction',
              name: 'direction',
              children: (
                <>
                  <option value="in">in</option>
                  <option value="out">out</option>
                </>
              ),
            })}

            {renderInput({
              label: 'Protocol',
              name: 'protocol',
              placeholder: '예: TCP, UDP, ICMP',
            })}

            {renderInput({
              label: 'Source Net',
              name: 'sourceNet',
              placeholder: '예: any, 192.168.1.0/24',
            })}

            {renderInput({
              label: 'Source Port',
              name: 'sourcePort',
              placeholder: '비워두면 any',
            })}

            {renderInput({
              label: 'Destination Net',
              name: 'destinationNet',
              placeholder: '예: any, 8.8.8.8',
            })}

            {renderInput({
              label: 'Destination Port',
              name: 'destinationPort',
              placeholder: '예: 80, 443',
            })}
          </div>

          <div className="rules-toolbar">
            <button
              type="button"
              className="rules-secondary-btn"
              onClick={() => setShowAdvanced((prev) => !prev)}
            >
              {showAdvanced ? '고급 숨기기' : '고급 표시'}
            </button>
          </div>

          {showAdvanced && (
            <div className="rules-advanced-box">
              <div>
                <h4>고급 옵션</h4>
                <p>룰 적용 시 로그 기록 여부를 설정합니다.</p>
              </div>

              <label className="rules-checkbox">
                <input
                  type="checkbox"
                  checked={form.log}
                  name="log"
                  onChange={handleChange}
                />
                <span>로그 남기기</span>
              </label>
            </div>
          )}

          <div className="rules-form-actions">
            <button className="rules-primary-btn" disabled={submitting}>
              {submitting ? '추가 중...' : '룰 추가'}
            </button>

            <button
              type="button"
              className="rules-reset-btn"
              onClick={resetForm}
            >
              초기화
            </button>
          </div>
        </form>
      </section>

      <section className="rules-list-panel">
        <div className="rules-panel-header">
          <div>
            <p className="rules-eyebrow">Policy List</p>
            <h2>룰 목록</h2>
          </div>

          <div className="rules-target-chip">총 {rules.length}개</div>
        </div>

        <div className="rules-table-outer">
          <div className="rules-table-inner">
            <table className="rules-table">
              <thead>
                <tr>
                  <th>설명</th>
                  <th>인터페이스</th>
                  <th>Action</th>
                  <th>Protocol</th>
                  <th>삭제</th>
                </tr>
              </thead>

              <tbody>
                {rules.length === 0 ? (
                  <tr>
                    <td colSpan="5" className="rules-empty">
                      룰이 없습니다.
                    </td>
                  </tr>
                ) : (
                  rules.map((rule, idx) => {
                    const id = rule.uuid || rule.id || idx
                    const description = rule.description || rule.descr || '-'
                    const ruleInterface = rule.interface || rule.if || '-'
                    const action = rule.action || '-'
                    const protocol = rule.protocol || '-'

                    return (
                      <tr key={id}>
                        <td>
                          <div className="rule-description-cell">
                            <div className="rule-avatar">
                              {String(description || '-')
                                .charAt(0)
                                .toUpperCase()}
                            </div>

                            <div>
                              <p>{description}</p>
                              <span>
                                {rule.uuid || rule.id || 'local-rule'}
                              </span>
                            </div>
                          </div>
                        </td>

                        <td>{ruleInterface}</td>
                        <td>{renderActionBadge(action)}</td>
                        <td>{protocol}</td>

                        <td>
                          <button
                            className="rules-delete-btn"
                            onClick={() =>
                              handleDeleteRule(
                                rule.uuid || rule.id,
                                rule.description || rule.descr || '',
                              )
                            }
                          >
                            삭제
                          </button>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>

            <div className="rules-table-footer">
              <div className="rules-page-info">
                표시 중: {rules.length}개 룰
              </div>

              <div className="rules-pagination">
                <button type="button" disabled>
                  <svg viewBox="0 0 1792 1792" aria-hidden="true">
                    <path d="M1427 301l-531 531 531 531q19 19 19 45t-19 45l-166 166q-19 19-45 19t-45-19l-742-742q-19-19-19-45t19-45l742-742q19-19 45-19t45 19l166 166q19 19 19 45t-19 45z" />
                  </svg>
                </button>

                <button type="button" className="active">
                  1
                </button>

                <button type="button" disabled>
                  <svg viewBox="0 0 1792 1792" aria-hidden="true">
                    <path d="M1363 877l-742 742q-19 19-45 19t-45-19l-166-166q-19-19-19-45t19-45l531-531-531-531q-19-19-19-45t19-45l166-166q19-19 45-19t45 19l742 742q19 19 19 45t-19 45z" />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}

export default RulesPage
