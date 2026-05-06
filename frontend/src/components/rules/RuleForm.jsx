function RuleForm({
  form,
  showAdvanced,
  setShowAdvanced,
  submitting,
  handleChange,
  handleAddRule,
  resetForm,
}) {
  return (
    <div className="card form-card">
      <div className="section-header">
        <h3>➕ 룰 추가</h3>
        <button type="button" onClick={() => setShowAdvanced((prev) => !prev)}>
          {showAdvanced ? '고급 옵션 숨기기' : '고급 옵션 보기'}
        </button>
      </div>

      <form onSubmit={handleAddRule}>
        <div className="form-grid">
          <div>
            <label>설명</label>
            <input
              name="description"
              value={form.description}
              onChange={handleChange}
              placeholder="예: dashboard block test"
              required
            />
          </div>

          <div>
            <label>액션</label>
            <select name="action" value={form.action} onChange={handleChange}>
              <option value="pass">허용(pass)</option>
              <option value="block">차단(block)</option>
            </select>
          </div>

          <div>
            <label>인터페이스</label>
            <select
              name="interface"
              value={form.interface}
              onChange={handleChange}
            >
              <option value="lan">LAN</option>
              <option value="wan">WAN</option>
            </select>
          </div>

          <div>
            <label>방향</label>
            <select
              name="direction"
              value={form.direction}
              onChange={handleChange}
            >
              <option value="in">IN</option>
              <option value="out">OUT</option>
            </select>
          </div>

          <div>
            <label>프로토콜</label>
            <select
              name="protocol"
              value={form.protocol}
              onChange={handleChange}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="TCP/UDP">TCP/UDP</option>
              <option value="ICMP">ICMP</option>
              <option value="any">ANY</option>
            </select>
          </div>

          <div>
            <label>출발지 IP / 네트워크</label>
            <input
              name="sourceNet"
              value={form.sourceNet}
              onChange={handleChange}
              placeholder="any 또는 192.168.1.100"
            />
          </div>

          <div>
            <label>출발지 포트</label>
            <input
              name="sourcePort"
              value={form.sourcePort}
              onChange={handleChange}
              placeholder="비워두면 전체"
            />
          </div>

          <div>
            <label>목적지 IP / 네트워크</label>
            <input
              name="destinationNet"
              value={form.destinationNet}
              onChange={handleChange}
              placeholder="any 또는 192.168.44.1"
            />
          </div>

          <div>
            <label>목적지 포트</label>
            <input
              name="destinationPort"
              value={form.destinationPort}
              onChange={handleChange}
              placeholder="예: 80, 443"
            />
          </div>
        </div>

        {showAdvanced && (
          <div className="advanced-box">
            <h4>고급 설정</h4>
            <div className="form-grid">
              <div>
                <label>활성화 여부</label>
                <select
                  name="enabled"
                  value={form.enabled}
                  onChange={handleChange}
                >
                  <option value="1">활성화</option>
                  <option value="0">비활성화</option>
                </select>
              </div>

              <div>
                <label>Quick</label>
                <select name="quick" value={form.quick} onChange={handleChange}>
                  <option value="1">사용</option>
                  <option value="0">미사용</option>
                </select>
              </div>

              <div className="checkbox-block">
                <label className="checkbox-inline">
                  <input
                    type="checkbox"
                    name="log"
                    checked={form.log}
                    onChange={handleChange}
                  />
                  로그 기록
                </label>
              </div>
            </div>
          </div>
        )}

        <div className="form-actions">
          <button type="submit" disabled={submitting}>
            {submitting ? '추가 중...' : '🚀 룰 추가'}
          </button>
          <button type="button" onClick={resetForm}>
            초기화
          </button>
        </div>
      </form>
    </div>
  )
}

export default RuleForm
