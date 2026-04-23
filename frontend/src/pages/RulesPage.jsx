function RulesPage({ rules, form, setForm, showAdvanced, setShowAdvanced, submitting, handleChange, handleAddRule, handleDeleteRule, resetForm, selectedFirewall }) {
  return (
    <div className="page main-grid">
      <div className="card form-card">
        <div className="section-header">
          <h3>룰 추가</h3>
          <div className="rule-count">대상: {selectedFirewall?.name || '-'}</div>
        </div>
        <form onSubmit={handleAddRule}>
          <div className="form-grid">
            <div><label>설명</label><input name="description" value={form.description} onChange={handleChange} /></div>
            <div><label>Action</label><select name="action" value={form.action} onChange={handleChange}><option value="pass">pass</option><option value="block">block</option><option value="reject">reject</option></select></div>
            <div><label>Interface</label><input name="interface" value={form.interface} onChange={handleChange} /></div>
            <div><label>Direction</label><select name="direction" value={form.direction} onChange={handleChange}><option value="in">in</option><option value="out">out</option></select></div>
            <div><label>Protocol</label><input name="protocol" value={form.protocol} onChange={handleChange} /></div>
            <div><label>Source Net</label><input name="sourceNet" value={form.sourceNet} onChange={handleChange} /></div>
            <div><label>Source Port</label><input name="sourcePort" value={form.sourcePort} onChange={handleChange} /></div>
            <div><label>Destination Net</label><input name="destinationNet" value={form.destinationNet} onChange={handleChange} /></div>
            <div><label>Destination Port</label><input name="destinationPort" value={form.destinationPort} onChange={handleChange} /></div>
          </div>
          <div className="form-actions">
            <button type="button" onClick={() => setShowAdvanced((prev) => !prev)}>{showAdvanced ? '고급 숨기기' : '고급 표시'}</button>
          </div>
          {showAdvanced && (
            <div className="advanced-box">
              <h4>고급 옵션</h4>
              <label className="checkbox-inline"><input type="checkbox" checked={form.log} name="log" onChange={handleChange} /> 로그 남기기</label>
            </div>
          )}
          <div className="form-actions">
            <button disabled={submitting}>{submitting ? '추가 중...' : '룰 추가'}</button>
            <button type="button" onClick={resetForm}>초기화</button>
          </div>
        </form>
      </div>
      <div className="card rules-card">
        <div className="section-header"><h3>룰 목록</h3><div className="rule-count">총 {rules.length}개</div></div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>설명</th><th>인터페이스</th><th>Action</th><th>Protocol</th><th>삭제</th></tr>
            </thead>
            <tbody>
              {rules.length === 0 ? <tr><td colSpan="5">룰이 없습니다.</td></tr> : rules.map((rule, idx) => (
                <tr key={rule.uuid || rule.id || idx}>
                  <td>{rule.description || rule.descr || '-'}</td>
                  <td>{rule.interface || rule.if || '-'}</td>
                  <td>{rule.action || '-'}</td>
                  <td>{rule.protocol || '-'}</td>
                  <td><button className="delete-btn" onClick={() => handleDeleteRule(rule.uuid || rule.id, rule.description || rule.descr || '')}>삭제</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default RulesPage
