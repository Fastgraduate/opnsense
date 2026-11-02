import { useEffect, useRef, useState } from 'react';
import { useAuth } from '../../auth/AuthContext';
export default function UserMenu({ onMyPage }) {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const root = useRef(null);
  const trigger = useRef(null);
  const timer = useRef(null);
  const cancelClose = () => clearTimeout(timer.current);
  const close = () => { cancelClose(); setOpen(false); };
  useEffect(() => {
    const outside = event => { if (!root.current?.contains(event.target)) setOpen(false); };
    document.addEventListener('pointerdown', outside);
    return () => { document.removeEventListener('pointerdown', outside); clearTimeout(timer.current); };
  }, []);
  const keyDown = event => {
    if (event.key === 'Escape') { event.preventDefault(); close(); trigger.current?.focus(); }
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
      event.preventDefault(); setOpen(true);
      requestAnimationFrame(() => {
        const items = [...root.current.querySelectorAll('[role="menuitem"]')];
        const index = items.indexOf(document.activeElement);
        const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (index + (event.key === 'ArrowUp' ? -1 : 1) + items.length) % items.length;
        items[next]?.focus();
      });
    }
  };
  return <div ref={root} className="profile-menu" onKeyDown={keyDown}
    onPointerEnter={event => { if (event.pointerType === 'mouse') { cancelClose(); setOpen(true); } }}
    onPointerLeave={event => { if (event.pointerType === 'mouse') timer.current = setTimeout(() => { if (!root.current?.contains(document.activeElement)) setOpen(false); }, 160); }}
    onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) close(); }}>
    <button ref={trigger} type="button" className={`profile-trigger ${open ? 'is-open' : ''}`} aria-label={`${user?.name || '사용자'}님 계정 메뉴`} aria-haspopup="menu" aria-expanded={open} aria-controls="profile-actions" onClick={() => { cancelClose(); setOpen(value => !value); }}>
      <span className="profile-avatar" aria-hidden="true"><svg viewBox="0 0 24 24"><circle cx="12" cy="8" r="3.5"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/></svg></span>
      <span className="profile-name">{user?.name}님</span>
      <svg className="profile-chevron" viewBox="0 0 20 20" aria-hidden="true"><path d="m5 7.5 5 5 5-5"/></svg>
    </button>
    {open && <div className="profile-popover"><div className="profile-panel" id="profile-actions" role="menu" aria-label="계정 메뉴">
      <button type="button" role="menuitem" onClick={() => { close(); onMyPage(); }}><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="8" r="3.5"/><path d="M5 21v-2a7 7 0 0 1 14 0v2"/></svg><span>마이페이지</span></button>
      <div className="profile-divider" role="separator" />
      <button type="button" role="menuitem" className="profile-logout" disabled={busy} onClick={async () => { setBusy(true); setError(''); try { await logout(); } catch { setError('로그아웃하지 못했습니다. 다시 시도해 주세요.'); } finally { setBusy(false); } }}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 4H4v16h5M9 12h12m-5-5 5 5-5 5"/></svg><span>{busy ? '로그아웃 중…' : '로그아웃'}</span></button>
      {error && <p className="profile-error" role="alert">{error}</p>}
    </div></div>}
  </div>;
}
