import { useCanManage } from '../auth/AuthContext';
import { twc } from "../lib/twc";
function RulesPage({
  rules,
  form,
  showAdvanced,
  setShowAdvanced,
  submitting,
  handleChange,
  handleAddRule,
  handleDeleteRule,
  resetForm,
  selectedFirewall
}) {
  const canManage = useCanManage();
  const getActionClass = action => {
    const value = String(action || '').toLowerCase();
    if (value === 'pass') return 'action-pass';
    if (value === 'block') return 'action-block';
    if (value === 'reject') return 'action-reject';
    return 'action-default';
  };
  const renderActionBadge = action => {
    const value = action || '-';
    return <span className={twc(`rule-action-badge ${getActionClass(value)}`)}>
        <span aria-hidden="true" />
        <strong>{value}</strong>
      </span>;
  };
  const renderInput = ({
    label,
    name,
    placeholder,
    required = false
  }) => <div className={twc("rule-input-field")}>
      <label htmlFor={name}>
        {label}
        {required ? <span className={twc("required-dot")}>*</span> : null}
      </label>

      <input id={name} name={name} value={form[name]} onChange={handleChange} placeholder={placeholder} />
    </div>;
  const renderSelect = ({
    label,
    name,
    children,
    required = false
  }) => <div className={twc("rule-input-field")}>
      <label htmlFor={name}>
        {label}
        {required ? <span className={twc("required-dot")}>*</span> : null}
      </label>

      <div className={twc("rule-select-wrap")}>
        <select id={name} name={name} value={form[name]} onChange={handleChange}>
          {children}
        </select>

        <span className={twc("rule-select-icon")}>
          <svg viewBox="0 0 20 20" aria-hidden="true">
            <path fillRule="evenodd" d="M10 3a1 1 0 01.707.293l3 3a1 1 0 01-1.414 1.414L10 5.414 7.707 7.707a1 1 0 01-1.414-1.414l3-3A1 1 0 0110 3zm-3.707 9.293a1 1 0 011.414 0L10 14.586l2.293-2.293a1 1 0 011.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </span>
      </div>
    </div>;
  return <div className={twc("rules-page")}>
      <section className={twc("rules-form-panel")} aria-label="룰 추가" tabIndex={0}>
        <div className={twc("rules-panel-header")}>
          <div>
            <p className={twc("rules-eyebrow")}>Firewall Policy</p>
            <h2>룰 추가</h2>
          </div>

          <div className={twc("rules-target-chip")}>
            대상: {selectedFirewall?.name || '-'}
          </div>
        </div>

        <form onSubmit={handleAddRule}><fieldset disabled={!canManage} style={{display: 'contents'}}>
          <div className={twc("rules-form-grid")}>
            {renderInput({
            label: '설명',
            name: 'description',
            placeholder: '예: Allow web traffic',
            required: true
          })}

            {renderSelect({
            label: 'Action',
            name: 'action',
            required: true,
            children: <>
                  <option value="pass">pass</option>
                  <option value="block">block</option>
                  <option value="reject">reject</option>
                </>
          })}

            {renderInput({
            label: 'Interface',
            name: 'interface',
            placeholder: '예: lan, wan',
            required: true
          })}

            {renderSelect({
            label: 'Direction',
            name: 'direction',
            children: <>
                  <option value="in">in</option>
                  <option value="out">out</option>
                </>
          })}

            {renderInput({
            label: 'Protocol',
            name: 'protocol',
            placeholder: '예: TCP, UDP, ICMP'
          })}

            {renderInput({
            label: 'Source Net',
            name: 'sourceNet',
            placeholder: '예: any, 192.168.1.0/24'
          })}

            {renderInput({
            label: 'Source Port',
            name: 'sourcePort',
            placeholder: '비워두면 any'
          })}

            {renderInput({
            label: 'Destination Net',
            name: 'destinationNet',
            placeholder: '예: any, 8.8.8.8'
          })}

            {renderInput({
            label: 'Destination Port',
            name: 'destinationPort',
            placeholder: '예: 80, 443'
          })}
          </div>

          <div className={twc("rules-toolbar")}>
            <button type="button" className={twc("ui-control-btn w-full")} aria-expanded={showAdvanced} aria-controls="rules-advanced-options" onClick={() => setShowAdvanced(prev => !prev)}>
              {showAdvanced ? '고급 숨기기' : '고급 표시'}
            </button>
          </div>

          {showAdvanced && <div id="rules-advanced-options" className={twc("rules-advanced-box")}>
              <div>
                <h4>고급 옵션</h4>
                <p>룰 적용 시 로그 기록 여부를 설정합니다.</p>
              </div>

              <label className={twc("rules-checkbox")}>
                <input type="checkbox" checked={form.log} name="log" onChange={handleChange} />
                <span>로그 남기기</span>
              </label>
            </div>}

          <div className={twc("rules-form-actions")}>
            <button className={twc("ui-control-btn ui-control-btn-primary w-full")} disabled={submitting}>
              {submitting ? '추가 중...' : '룰 추가'}
            </button>

            <button type="button" className={twc("ui-control-btn w-full")} onClick={resetForm}>
              초기화
            </button>
          </div>
        </fieldset></form>
      </section>

      <section className={twc("rules-list-panel")} style={{ padding: 16, minWidth: 0, overflow: "hidden" }}>
        <div className={twc("rules-panel-header")}>
          <div>
            <p className={twc("rules-eyebrow")}>Policy List</p>
            <h2>룰 목록</h2>
          </div>

          <div className={twc("rules-target-chip")}>총 {rules.length}개</div>
        </div>

        <div className={twc("rules-table-outer")}>
          <div className={twc("rules-table-inner")}>
            <table className={twc("rules-table")}>
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
                {rules.length === 0 ? <tr>
                    <td colSpan="5" className={twc("rules-empty")}>
                      룰이 없습니다.
                    </td>
                  </tr> : rules.map((rule, idx) => {
                const id = rule.uuid || rule.id || idx;
                const description = rule.description || rule.descr || '-';
                const ruleInterface = rule.interface || rule.if || '-';
                const action = rule.action || '-';
                const protocol = rule.protocol || '-';
                return <tr key={id}>
                        <td>
                          <div className={twc("rule-description-cell")}>
                            <div className={twc("rule-avatar")}>
                              {String(description || '-').charAt(0).toUpperCase()}
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
                          <button className={twc("ui-control-btn ui-control-btn-danger")} disabled={!canManage} onClick={() => handleDeleteRule(rule.uuid || rule.id, rule.description || rule.descr || '')}>
                            삭제
                          </button>
                        </td>
                      </tr>;
              })}
              </tbody>
            </table>

            <div className={twc("rules-table-footer")}>
              <div className={twc("rules-page-info")}>
                표시 중: {rules.length}개 룰
              </div>

              <div className={twc("rules-pagination")}>
                <button type="button" disabled>
                  <svg viewBox="0 0 1792 1792" aria-hidden="true">
                    <path d="M1427 301l-531 531 531 531q19 19 19 45t-19 45l-166 166q-19 19-45 19t-45-19l-742-742q-19-19-19-45t19-45l742-742q19-19 45-19t45 19l166 166q19 19 19 45t-19 45z" />
                  </svg>
                </button>

                <button type="button" className={twc("active")}>
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
    </div>;
}
export default RulesPage;
