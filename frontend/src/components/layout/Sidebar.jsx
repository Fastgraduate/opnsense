const icons = {
  dashboard: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
    </svg>
  ),
  rules: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 4h16v2H4V4zm0 5h16v2H4V9zm0 5h10v2H4v-2zm0 5h10v2H4v-2zm13.7-1.7 3.6-3.6 1.4 1.4-5 5-3-3 1.4-1.4 1.6 1.6z" />
    </svg>
  ),
  eventLogs: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2 4 5v6c0 5.1 3.4 9.9 8 11 4.6-1.1 8-5.9 8-11V5l-8-3zm0 2.2L18 6.5V11c0 4-2.5 7.7-6 8.8C8.5 18.7 6 15 6 11V6.5l6-2.3zm-1 4.8h2v5h-2V9zm0 6h2v2h-2v-2z" />
    </svg>
  ),
  firewalls: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 4h18v16H3V4zm2 2v3h4V6H5zm6 0v3h4V6h-4zm6 0v3h2V6h-2zM5 11v3h2v-3H5zm4 0v3h4v-3H9zm6 0v3h4v-3h-4zM5 16v2h4v-2H5zm6 0v2h4v-2h-4zm6 0v2h2v-2h-2z" />
    </svg>
  ),
  logs: (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M6 2h9l5 5v15H6V2zm8 1.8V8h4.2L14 3.8zM8 11h8v2H8v-2zm0 4h8v2H8v-2zm0-8h4v2H8V7zM4 6v18h14v-2H6V6H4z" />
    </svg>
  ),
}

function Sidebar({ currentPage, setCurrentPage }) {
  const items = [
    ['dashboard', '대시보드'],
    ['rules', '룰 관리'],
    ['eventLogs', '방화벽 이벤트 로그'],
    ['firewalls', '방화벽 관리'],
    ['logs', '앱 로그'],
  ]

  return (
    <aside className="sidebar modern-sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-logo">O</div>
        <div>
          <div className="sidebar-title">OPNsense</div>
          <div className="sidebar-subtitle">Manager</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {items.map(([key, label]) => (
          <button
            key={key}
            className={`sidebar-menu modern-sidebar-menu ${
              currentPage === key ? 'active' : ''
            }`}
            onClick={() => setCurrentPage(key)}
          >
            <span className="sidebar-menu-icon">{icons[key]}</span>
            <span className="sidebar-menu-label">{label}</span>
          </button>
        ))}
      </nav>
    </aside>
  )
}

export default Sidebar
