import { twc } from "../../lib/twc";
import { SECTION_DECKS_BY_ID } from '../../navigation/sectionDecks';
const icons = {
  dashboard: <svg viewBox="0 0 24 24">
      <path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z" />
    </svg>,
  rules: <svg viewBox="0 0 24 24">
      <path d="M4 4h16v2H4V4zm0 5h16v2H4V9zm0 5h10v2H4v-2zm0 5h10v2H4v-2zm13.7-1.7 3.6-3.6 1.4 1.4-5 5-3-3 1.4-1.4 1.6 1.6z" />
    </svg>,
  eventLogs: <svg viewBox="0 0 24 24">
      <path d="M12 2 4 5v6c0 5.1 3.4 9.9 8 11 4.6-1.1 8-5.9 8-11V5l-8-3zm-1 7h2v5h-2V9zm0 6h2v2h-2v-2z" />
    </svg>,
  securityAlerts: <svg viewBox="0 0 24 24">
      <path d="M12 2 1 21h22L12 2zm0 4.1L19.5 19h-15L12 6.1zM11 10h2v5h-2v-5zm0 6h2v2h-2v-2z" />
    </svg>,
  opnsense: <svg viewBox="0 0 24 24">
      <path d="M3 4h18v16H3V4zm2 2v3h4V6H5zm6 0v3h4V6h-4zm6 0v3h2V6h-2zM5 11v3h2v-3H5zm4 0v3h4v-3H9zm6 0v3h4v-3h-4zM5 16v2h4v-2H5zm6 0v2h4v-2h-4zm6 0v2h2v-2h-2z" />
    </svg>,
  firewalls: <svg viewBox="0 0 24 24">
      <path d="M3 4h18v16H3V4zm2 2v12h14V6H5z" />
    </svg>,
  logs: <svg viewBox="0 0 24 24">
      <path d="M6 2h9l5 5v15H6V2zm8 1.8V8h4.2L14 3.8zM8 11h8v2H8v-2zm0 4h8v2H8v-2zM4 6v18h14v-2H6V6H4z" />
    </svg>
};
function Sidebar({
  currentPage,
  setCurrentPage,
  mobileOpen = false,
  onClose
}) {
  const navigate = page => {
    setCurrentPage(page);
    onClose?.();
  };
  const sectionButton = ({
    sectionId,
    icon,
    label,
    nested = false
  }) => {
    const section = SECTION_DECKS_BY_ID[sectionId];
    const active = section.pages.some(page => page.id === currentPage);
    return <button
      type="button"
      className={twc(`sidebar-menu modern-sidebar-menu focus:outline-none focus-visible:outline-none focus-visible:ring-0 ${nested ? 'sidebar-nested-menu' : ''} ${active ? 'active' : ''}`)}
      onClick={() => navigate(section.pages[0].id)}
    >
        <span className={twc("sidebar-menu-icon")}>{icons[icon]}</span>
        <span className={twc("sidebar-menu-label")}>{label || section.label}</span>
        <span className={twc("sidebar-menu-tail")} aria-hidden="true">
          <small>{section.pages.length}</small>
          <svg viewBox="0 0 20 20"><path d="m7.5 4.5 5.5 5.5-5.5 5.5-1.4-1.4 4.1-4.1-4.1-4.1 1.4-1.4Z" /></svg>
        </span>
      </button>;
  };
  return <>
      {mobileOpen ? <button type="button" aria-label="메뉴 닫기" className={twc("fixed inset-0 z-40 bg-slate-950/40 backdrop-blur-sm lg:hidden")} onClick={onClose} /> : null}

    <aside className={twc(`sidebar modern-sidebar liquid-navigation fixed inset-y-3 left-3 z-50 overflow-hidden rounded-[30px] border border-white/50 bg-white/52 shadow-[0_28px_80px_rgba(31,38,70,.18)] backdrop-blur-3xl transition-transform duration-300 dark:border-white/10 dark:bg-slate-950/72 lg:sticky lg:inset-y-3 lg:left-3 lg:top-3 lg:z-20 lg:h-[calc(100dvh-24px)] lg:translate-x-0 lg:rounded-[30px] ${mobileOpen ? 'translate-x-0' : '-translate-x-[120%]'}`)}>
      <div className={twc("sidebar-brand")}>
        <div className={twc("sidebar-logo")} aria-hidden="true">
          <svg viewBox="0 0 40 40" role="presentation">
            <path className={twc("sidebar-logo-shield")} d="M20 4.5 32 9v9.4c0 8-4.8 13.7-12 17.1C12.8 32.1 8 26.4 8 18.4V9l12-4.5Z" />
            <circle className={twc("sidebar-logo-ring")} cx="20" cy="19" r="6.4" />
            <circle className={twc("sidebar-logo-core")} cx="20" cy="19" r="2.15" />
            <path className={twc("sidebar-logo-link")} d="M20 12.6V9.8M13.6 19h-2.8M26.4 19h2.8M20 25.4v2.8" />
          </svg>
        </div>
        <div>
          <div className={twc("sidebar-title dark:text-white")}>OPNsense</div>
          <div className={twc("sidebar-subtitle")}>Security Intelligence</div>
        </div>
        <button type="button" className={twc("ml-auto flex h-9 w-9 items-center justify-center rounded-xl border border-white/60 bg-white/50 text-slate-500 dark:border-white/10 dark:bg-white/5 dark:text-slate-300 lg:hidden")} onClick={onClose} aria-label="메뉴 닫기">×</button>
      </div>

      <nav className={twc("sidebar-nav")}>
        <button type="button" className={twc(`sidebar-menu modern-sidebar-menu focus:outline-none focus-visible:outline-none focus-visible:ring-0 ${currentPage === 'dashboard' ? 'active' : ''}`)} onClick={() => navigate('dashboard')}>
          <span className={twc("sidebar-menu-icon")}>{icons.dashboard}</span>
          <span className={twc("sidebar-menu-label")}>대시보드</span>
        </button>

        <div className={twc("sidebar-section-group")}>
          <div className={twc("sidebar-section-label")} aria-hidden="true">
            <span>OPNsense</span>
          </div>
          <div className={twc("sidebar-section-items")}>
            {sectionButton({
              sectionId: 'rules',
              icon: 'rules',
              label: '룰 관리',
              nested: true
            })}
            {sectionButton({
              sectionId: 'opnsense',
              icon: 'opnsense',
              label: 'OPNsense 로그',
              nested: true
            })}
          </div>
        </div>

        <div className={twc("sidebar-section-group")}>
          <div className={twc("sidebar-section-label")} aria-hidden="true">
            <span>ELK</span>
          </div>
          <div className={twc("sidebar-section-items")}>
            {sectionButton({
              sectionId: 'security',
              icon: 'securityAlerts',
              label: '실시간 공격 탐지',
              nested: true
            })}
            {sectionButton({ sectionId: 'blocks', icon: 'eventLogs', label: '차단 IP 목록', nested: true })}
          </div>
        </div>

        <button type="button" className={twc(`sidebar-menu modern-sidebar-menu focus:outline-none focus-visible:outline-none focus-visible:ring-0 ${currentPage === 'firewalls' ? 'active' : ''}`)} onClick={() => navigate('firewalls')}>
          <span className={twc("sidebar-menu-icon")}>{icons.firewalls}</span>
          <span className={twc("sidebar-menu-label")}>방화벽 관리</span>
        </button>

        <button type="button" className={twc(`sidebar-menu modern-sidebar-menu focus:outline-none focus-visible:outline-none focus-visible:ring-0 ${currentPage === 'logs' ? 'active' : ''}`)} onClick={() => navigate('logs')}>
          <span className={twc("sidebar-menu-icon")}>{icons.logs}</span>
          <span className={twc("sidebar-menu-label")}>앱 로그</span>
        </button>

      </nav>
      <div className={twc("sidebar-footer")}>
        <div className={twc("flex items-center gap-2")}>
          <span className={twc("h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,.8)] animate-status-pulse")} />
          <strong className={twc("text-xs font-black text-slate-700 dark:text-slate-200")}>Security Engine</strong>
        </div>
        <p className={twc("mt-1 text-[10px] font-bold leading-4 text-slate-400")}>OPNsense · ELK · V32 ML</p>
      </div>
    </aside>
    </>;
}
export default Sidebar;
