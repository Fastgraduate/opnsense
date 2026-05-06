function Sidebar({ currentPage, setCurrentPage }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-title">OPNsense Admin</div>

      <button
        className={`sidebar-menu ${currentPage === 'dashboard' ? 'active' : ''}`}
        onClick={() => setCurrentPage('dashboard')}
      >
        📊 대시보드
      </button>

      <button
        className={`sidebar-menu ${currentPage === 'rules' ? 'active' : ''}`}
        onClick={() => setCurrentPage('rules')}
      >
        🔥 룰 확인 / 추가
      </button>

      <button
        className={`sidebar-menu ${currentPage === 'logs' ? 'active' : ''}`}
        onClick={() => setCurrentPage('logs')}
      >
        📜 로그 확인
      </button>
    </aside>
  )
}

export default Sidebar
