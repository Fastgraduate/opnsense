import UserMenu from './UserMenu';
import { twc } from "../../lib/twc";
import { useTheme } from '../ui/themeContext';
const PAGE_META = {
  myPage: ['My Account', '마이페이지'],
  dashboard: ['Overview', '통합 대시보드'],
  rules: ['Firewall Policy', '룰 관리'],
  interfaceRules: ['Firewall Policy', '룰 관리'],
  eventLogIndex: ['Live Detections', '실시간 공격 탐지'],
  eventLogSqlSearch: ['Live Detections', '실시간 공격 탐지'],
  securityAlerts: ['Live Detections', '실시간 공격 탐지'],
  blockedIps: ['Blocked Addresses', '차단 IP 목록'],
  automaticBlockedIps: ['Blocked Addresses', '차단 IP 목록'],
  opnsenseLogOverview: ['OPNsense Logs', 'OPNsense 로그 파일'],
  opnsenseLogs: ['OPNsense Logs', 'OPNsense 로그 파일'],
  firewalls: ['Connections', '방화벽 관리'],
  logs: ['Application', '앱 로그']
};
function SunIcon() {
  return <svg viewBox="0 0 24 24" className={twc("h-5 w-5 fill-none stroke-current")} strokeWidth="1.8"><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.66 6.34l1.41-1.41" /></svg>;
}
function MoonIcon() {
  return <svg viewBox="0 0 24 24" className={twc("h-5 w-5 fill-none stroke-current")} strokeWidth="1.8"><path d="M20.2 15.2A8.4 8.4 0 0 1 8.8 3.8 8.5 8.5 0 1 0 20.2 15.2Z" /></svg>;
}
export default function AppTopbar({
  currentPage,
  selectedFirewall,
  onOpenSidebar,
  onMyPage
}) {
  const {
    theme,
    toggleTheme
  } = useTheme();
  const [eyebrow, title] = PAGE_META[currentPage] || PAGE_META.dashboard;
  return <header style={{ contain: 'none', overflow: 'visible' }} className={twc("liquid-navigation sticky top-3 z-30 mx-auto mt-3 flex min-h-[64px] w-[calc(100%-24px)] max-w-[980px] items-center gap-3 overflow-visible rounded-[26px] border border-white/60 bg-white/48 px-3 shadow-[inset_0_1px_0_rgba(255,255,255,.75),0_20px_55px_rgba(38,45,78,.12)] backdrop-blur-3xl backdrop-saturate-150 before:pointer-events-none before:absolute before:inset-0 before:bg-[radial-gradient(circle_at_var(--glass-x)_var(--glass-y),rgba(255,255,255,.42),transparent_31%)] before:opacity-40 after:pointer-events-none after:absolute after:inset-0 after:bg-[linear-gradient(110deg,transparent_26%,rgba(255,255,255,.22)_48%,transparent_68%)] after:bg-[length:220%_100%] after:opacity-20 after:animate-[liquidGlassSweep_9s_ease-in-out_infinite] dark:border-white/12 dark:bg-slate-950/52 dark:before:bg-[radial-gradient(circle_at_var(--glass-x)_var(--glass-y),rgba(125,211,252,.13),transparent_34%)] lg:px-4 [&>*]:relative [&>*]:z-10")}>
      <button type="button" className={twc("flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-white/60 bg-white/55 text-slate-700 shadow-sm backdrop-blur-xl dark:border-white/10 dark:bg-white/5 dark:text-slate-200 lg:hidden")} onClick={onOpenSidebar} aria-label="메뉴 열기">
        <svg viewBox="0 0 24 24" className={twc("h-5 w-5 fill-none stroke-current")} strokeWidth="2"><path d="M4 7h16M4 12h16M4 17h16" /></svg>
      </button>

      <div className={twc("min-w-0 flex-1 text-left")}>
        <p className={twc("m-0 text-[10px] font-black uppercase tracking-[.2em] text-violet-600 dark:text-violet-300")}>{eyebrow}</p>
        <h1 className={twc("m-0 truncate text-lg font-black tracking-tight text-slate-950 dark:text-white lg:text-xl")}>{title}</h1>
      </div>

      <div className={twc("hidden items-center gap-2 rounded-2xl border border-white/60 bg-white/45 px-3 py-2 backdrop-blur-xl dark:border-white/10 dark:bg-white/[.035] sm:flex")}>
        <span className={twc(`h-2 w-2 rounded-full ${selectedFirewall ? 'bg-emerald-400 shadow-[0_0_14px_rgba(52,211,153,.9)] animate-status-pulse' : 'bg-slate-400'}`)} />
        <div className={twc("max-w-48 text-left")}>
          <p className={twc("m-0 text-[10px] font-extrabold text-slate-400")}>현재 연결</p>
          <strong className={twc("block truncate text-xs font-black text-slate-700 dark:text-slate-200")}>{selectedFirewall?.name || '방화벽 미선택'}</strong>
        </div>
      </div>

      <UserMenu onMyPage={onMyPage} />
      <button type="button" className={twc("flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl border border-white/60 bg-white/55 text-slate-600 shadow-sm backdrop-blur-xl dark:border-white/10 dark:bg-white/5 dark:text-slate-200")} onClick={toggleTheme} aria-label={theme === 'dark' ? '라이트 모드' : '다크 모드'}>
        {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
      </button>
    </header>;
}
