function RuleTable({ rules, loading, handleDeleteRule }) {
  return (
    <div className="card rules-card">
      <div className="section-header">
        <h3>🔥 방화벽 룰 목록</h3>
        <span className="rule-count">총 {rules.length}개</span>
      </div>

      {loading ? (
        <p className="loading">로딩 중...</p>
      ) : rules.length === 0 ? (
        <p className="empty-text">현재 생성된 자동 규칙이 없습니다.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>설명</th>
                <th>액션</th>
                <th>인터페이스</th>
                <th>방향</th>
                <th>프로토콜</th>
                <th>출발지</th>
                <th>목적지</th>
                <th>삭제</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.uuid}>
                  <td>{rule.description || '-'}</td>
                  <td>{rule.action || '-'}</td>
                  <td>{rule.interface || '-'}</td>
                  <td>{rule.direction || '-'}</td>
                  <td>{rule.protocol || '-'}</td>
                  <td>
                    {rule.source_net || '-'}
                    {rule.source_port ? `:${rule.source_port}` : ''}
                  </td>
                  <td>
                    {rule.destination_net || '-'}
                    {rule.destination_port ? `:${rule.destination_port}` : ''}
                  </td>
                  <td>
                    <button
                      className="delete-btn"
                      onClick={() =>
                        handleDeleteRule(rule.uuid, rule.description)
                      }
                    >
                      ❌ 삭제
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default RuleTable
