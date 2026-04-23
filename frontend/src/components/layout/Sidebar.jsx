function Sidebar({ currentPage, setCurrentPage }) {
  const items = [
    ['dashboard', '대시보드'],
    ['rules', '룰 관리'],
    ['eventLogs', '방화벽 이벤트 로그'],
    ['firewalls', '방화벽 관리'],
    ['logs', '앱 로그'],
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-title">OPNsense Manager</div>
      {items.map(([key, label]) => (
        <button
          key={key}
          className={`sidebar-menu ${currentPage === key ? 'active' : ''}`}
          onClick={() => setCurrentPage(key)}
        >
          {label}
        </button>
      ))}
    </aside>
  )
}

export default Sidebar
