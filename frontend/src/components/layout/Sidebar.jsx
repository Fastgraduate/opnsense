import { useState } from 'react'

const icons = {
  dashboard: (
    <svg viewBox="0 0 24 24">
      <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
    </svg>
  ),
  rules: (
    <svg viewBox="0 0 24 24">
      <path d="M4 4h16v2H4V4zm0 5h16v2H4V9zm0 5h10v2H4v-2zm0 5h10v2H4v-2zm13.7-1.7 3.6-3.6 1.4 1.4-5 5-3-3 1.4-1.4 1.6 1.6z" />
    </svg>
  ),
  eventLogs: (
    <svg viewBox="0 0 24 24">
      <path d="M12 2 4 5v6c0 5.1 3.4 9.9 8 11 4.6-1.1 8-5.9 8-11V5l-8-3zm-1 7h2v5h-2V9zm0 6h2v2h-2v-2z" />
    </svg>
  ),
  securityAlerts: (
    <svg viewBox="0 0 24 24">
      <path d="M12 2 1 21h22L12 2zm0 4.1L19.5 19h-15L12 6.1zM11 10h2v5h-2v-5zm0 6h2v2h-2v-2z" />
    </svg>
  ),
  opnsense: (
    <svg viewBox="0 0 24 24">
      <path d="M3 4h18v16H3V4zm2 2v3h4V6H5zm6 0v3h4V6h-4zm6 0v3h2V6h-2zM5 11v3h2v-3H5zm4 0v3h4v-3H9zm6 0v3h4v-3h-4zM5 16v2h4v-2H5zm6 0v2h4v-2h-4zm6 0v2h2v-2h-2z" />
    </svg>
  ),
  firewalls: (
    <svg viewBox="0 0 24 24">
      <path d="M3 4h18v16H3V4zm2 2v12h14V6H5z" />
    </svg>
  ),
  logs: (
    <svg viewBox="0 0 24 24">
      <path d="M6 2h9l5 5v15H6V2zm8 1.8V8h4.2L14 3.8zM8 11h8v2H8v-2zm0 4h8v2H8v-2zM4 6v18h14v-2H6V6H4z" />
    </svg>
  ),
}

function Sidebar({ currentPage, setCurrentPage }) {
  const eventPages = ['eventLogs', 'eventLogIndex', 'eventLogSqlSearch']
  const rulePages = ['rules', 'interfaceRules']
  const opnPages = ['opnsenseLogOverview', 'opnsenseLogs']

  const [eventOpen, setEventOpen] = useState(eventPages.includes(currentPage))
  const [ruleOpen, setRuleOpen] = useState(rulePages.includes(currentPage))
  const [opnOpen, setOpnOpen] = useState(opnPages.includes(currentPage))

  const group = ({ label, icon, active, open, setOpen, main, subs }) => (
    <div className="sidebar-menu-group">
      <div
        className={`sidebar-menu modern-sidebar-menu sidebar-event-row ${
          active ? 'active' : ''
        }`}
      >
        <button
          type="button"
          className="sidebar-event-main"
          onClick={() => {
            setCurrentPage(main)
            setOpen(true)
          }}
        >
          <span className="sidebar-menu-icon">{icons[icon]}</span>
          <span className="sidebar-menu-label">{label}</span>
        </button>

        <button
          type="button"
          className={`sidebar-event-arrow ${open ? 'open' : ''}`}
          onClick={(e) => {
            e.preventDefault()
            e.stopPropagation()
            setOpen((prev) => !prev)
          }}
        >
          <svg viewBox="0 0 20 20">
            <path d="M6.2 7.2 10 11l3.8-3.8 1.4 1.4L10 13.8 4.8 8.6l1.4-1.4z" />
          </svg>
        </button>
      </div>

      {open ? (
        <div className="sidebar-submenu">
          {subs.map(([key, value]) => (
            <button
              key={key}
              type="button"
              className={`sidebar-submenu-item ${
                currentPage === key ? 'active' : ''
              }`}
              onClick={() => setCurrentPage(key)}
            >
              {value}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  )

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
        <button
          type="button"
          className={`sidebar-menu modern-sidebar-menu ${
            currentPage === 'dashboard' ? 'active' : ''
          }`}
          onClick={() => setCurrentPage('dashboard')}
        >
          <span className="sidebar-menu-icon">{icons.dashboard}</span>
          <span className="sidebar-menu-label">대시보드</span>
        </button>

        {group({
          label: '룰 관리',
          icon: 'rules',
          active: rulePages.includes(currentPage),
          open: ruleOpen,
          setOpen: setRuleOpen,
          main: 'rules',
          subs: [
            ['rules', '전체 룰'],
            ['interfaceRules', '인터페이스별 룰'],
          ],
        })}

        {group({
          label: '방화벽 이벤트 로그',
          icon: 'eventLogs',
          active: eventPages.includes(currentPage),
          open: eventOpen,
          setOpen: setEventOpen,
          main: 'eventLogs',
          subs: [
            ['eventLogIndex', '로그 인덱싱'],
            ['eventLogSqlSearch', 'SQL 로그 검색'],
          ],
        })}

        <button
          type="button"
          className={`sidebar-menu modern-sidebar-menu ${
            currentPage === 'securityAlerts' ? 'active' : ''
          }`}
          onClick={() => setCurrentPage('securityAlerts')}
        >
          <span className="sidebar-menu-icon">{icons.securityAlerts}</span>
          <span className="sidebar-menu-label">실시간 공격 알림</span>
        </button>

        {group({
          label: 'OPNsense 로그 파일',
          icon: 'opnsense',
          active: opnPages.includes(currentPage),
          open: opnOpen,
          setOpen: setOpnOpen,
          main: 'opnsenseLogOverview',
          subs: [
            ['opnsenseLogOverview', '개요'],
            ['opnsenseLogs', '실시간 보기'],
          ],
        })}

        <button
          type="button"
          className={`sidebar-menu modern-sidebar-menu ${
            currentPage === 'firewalls' ? 'active' : ''
          }`}
          onClick={() => setCurrentPage('firewalls')}
        >
          <span className="sidebar-menu-icon">{icons.firewalls}</span>
          <span className="sidebar-menu-label">방화벽 관리</span>
        </button>

        <button
          type="button"
          className={`sidebar-menu modern-sidebar-menu ${
            currentPage === 'logs' ? 'active' : ''
          }`}
          onClick={() => setCurrentPage('logs')}
        >
          <span className="sidebar-menu-icon">{icons.logs}</span>
          <span className="sidebar-menu-label">앱 로그</span>
        </button>
      </nav>
    </aside>
  )
}

export default Sidebar
