
function RulesPage({
  rules = [],
  loading,
  form,
  showAdvanced,
  setShowAdvanced,
  submitting,
  handleChange,
  handleAddRule,
  handleDeleteRule,
  resetForm,
  aliases = [],
  selectedFirewall,
}) {
  const rows = Array.isArray(rules) ? rules : []

  return (
    <div className="main-grid">
      <div className="card form-card">
        <div className="card-header-row">
          <h3>룰 추가</h3>
        </div>
        <p className="subtle-text">대상 방화벽: {selectedFirewall?.name || '-'}</p>

        <form onSubmit={handleAddRule}>
          <div className="form-grid">
            <div>
              <label>설명</label>
              <input name="description" value={form.description} onChange={handleChange} />
            </div>
            <div>
              <label>Action</label>
              <select name="action" value={form.action} onChange={handleChange}>
                <option value="pass">pass</option>
                <option value="block">block</option>
                <option value="reject">reject</option>
              </select>
            </div>
            <div>
              <label>Interface</label>
              <select name="interface" value={form.interface} onChange={handleChange}>
                <option value="lan">lan</option>
                <option value="wan">wan</option>
                <option value="opt1">opt1</option>
              </select>
            </div>
            <div>
              <label>Direction</label>
              <select name="direction" value={form.direction} onChange={handleChange}>
                <option value="in">in</option>
                <option value="out">out</option>
              </select>
            </div>
            <div>
              <label>Protocol</label>
              <select name="protocol" value={form.protocol} onChange={handleChange}>
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="ICMP">ICMP</option>
                <option value="any">any</option>
              </select>
            </div>
            <div>
              <label>Source Net</label>
              <input name="sourceNet" value={form.sourceNet} onChange={handleChange} />
            </div>
            <div>
              <label>Source Port</label>
              <input name="sourcePort" value={form.sourcePort} onChange={handleChange} />
            </div>
            <div>
              <label>Destination Net</label>
              <input name="destinationNet" value={form.destinationNet} onChange={handleChange} />
            </div>
            <div>
              <label>Destination Port</label>
              <input name="destinationPort" value={form.destinationPort} onChange={handleChange} />
            </div>
            <div className="checkbox-inline checkbox-row">
              <input id="log" name="log" type="checkbox" checked={form.log} onChange={handleChange} />
              <label htmlFor="log">로그 기록</label>
            </div>
          </div>

          <div className="form-actions">
            <button type="button" onClick={() => setShowAdvanced((prev) => !prev)}>
              {showAdvanced ? '고급옵션 숨기기' : '고급옵션 보기'}
            </button>
            <button type="submit" disabled={submitting}>
              {submitting ? '추가 중...' : '룰 추가'}
            </button>
            <button type="button" onClick={resetForm}>초기화</button>
          </div>

          {showAdvanced && (
            <div className="advanced-box">
              <h4>Alias 참고</h4>
              <p className="empty-text">{aliases.length ? aliases.join(', ') : '등록된 alias 없음'}</p>
            </div>
          )}
        </form>
      </div>

      <div className="card rules-card">
        <div className="section-header">
          <h3>룰 목록</h3>
          <span className="rule-count">{rows.length}개</span>
        </div>

        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Description</th>
                <th>Interface</th>
                <th>Direction</th>
                <th>Action</th>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>관리</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8}>불러오는 중...</td></tr>
              ) : rows.length === 0 ? (
                <tr><td colSpan={8}>룰이 없습니다.</td></tr>
              ) : (
                rows.map((rule, idx) => (
                  <tr key={rule.uuid || rule.id || idx}>
                    <td>{rule.description || rule.descr || '-'}</td>
                    <td>{rule.interface || rule.if || '-'}</td>
                    <td>{rule.direction || '-'}</td>
                    <td>{rule.action || '-'}</td>
                    <td>{rule.protocol || '-'}</td>
                    <td>{rule.source_net || rule.source || '-'}</td>
                    <td>{rule.destination_net || rule.destination || '-'}</td>
                    <td>
                      <button
                        className="delete-btn"
                        onClick={() => handleDeleteRule(rule.uuid, rule.description || rule.descr)}
                      >
                        삭제
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default RulesPage
