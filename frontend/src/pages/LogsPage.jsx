import LogList from '../components/logs/LogList'

function LogsPage({ logs, setLogs }) {
  return (
    <>
      <div className="page-header">
        <h2>로그 확인</h2>
        <p>대시보드 동작과 룰 변경 내역을 간단히 확인합니다.</p>
      </div>

      <div className="card">
        <div className="section-header">
          <h3>📜 이벤트 로그</h3>
          <button onClick={() => setLogs([])}>로그 비우기</button>
        </div>

        <LogList logs={logs} />
      </div>
    </>
  )
}

export default LogsPage
