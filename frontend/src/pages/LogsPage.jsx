function LogsPage({ logs = [], setLogs }) {
  return (
    <div className="page">
      <div className="card">
        <div className="card-header-row">
          <h3>앱 로그</h3>
          <button onClick={() => setLogs([])}>로그 비우기</button>
        </div>
        <div className="log-list">
          {logs.length === 0 ? <p>로그가 없습니다.</p> : logs.map((log) => (
            <div className="log-item" key={log.id}>
              <div className={`log-badge ${String(log.level || 'info').toLowerCase()}`}>{log.level}</div>
              <div className="log-content">
                <div className="log-message">{log.message}</div>
                <div className="log-time">{log.time}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default LogsPage
