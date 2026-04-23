
function Sidebar({ currentPage, setCurrentPage }) {
  const menus = [
    { id: 'dashboard', label: '대시보드' },
    { id: 'rules', label: '룰 관리' },
    { id: 'logs', label: '로그' },
    { id: 'firewalls', label: '방화벽 관리' },
  ]

  return (
    <aside className="sidebar">
      <div className="sidebar-title">OPNsense Manager</div>
      {menus.map((menu) => (
        <button
          key={menu.id}
          className={`sidebar-menu ${currentPage === menu.id ? 'active' : ''}`}
          onClick={() => setCurrentPage(menu.id)}
        >
          {menu.label}
        </button>
      ))}
    </aside>
  )
}

export default Sidebar
