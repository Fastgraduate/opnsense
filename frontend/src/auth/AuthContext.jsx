import { createContext, useContext, useEffect, useState } from 'react';
import { authRequest, clearAuth, notifyLogout, setAccessToken } from './api';
const Context = createContext(null);
export const useAuth = () => useContext(Context);
export const useCanManage = () => useAuth()?.user?.role === 'admin';
export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [connectionError, setConnectionError] = useState('');
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let alive = true;
    setLoading(true); setConnectionError('');
    authRequest('session', null, 'GET').then(data => {
      if (alive) { setSession(data); setMessage(''); }
    }).catch(error => {
      if (alive && error.status !== 401) setConnectionError('서버에 연결하지 못했습니다. 백엔드 실행 상태를 확인해 주세요.');
    }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [retry]);
  useEffect(() => {
    const expire = event => { setSession(null); setMessage(event.detail || ''); };
    window.addEventListener('dashboard:unauthorized', expire);
    const channel = 'BroadcastChannel' in window ? new BroadcastChannel('opnsense-auth') : null;
    if (channel) channel.onmessage = event => { if (event.data === 'logout') clearAuth('다른 탭에서 로그아웃했습니다.'); };
    return () => { window.removeEventListener('dashboard:unauthorized', expire); channel?.close(); };
  }, []);
  useEffect(() => {
    if (!session) return;
    const expire = () => {
      if (Date.now() >= session.expires_at * 1000) clearAuth('로그인 시간이 만료되었습니다. 다시 로그인해 주세요.');
    };
    const timer = window.setTimeout(expire, Math.min(2147483647, Math.max(0, session.expires_at * 1000 - Date.now())));
    const leave = () => {
      if (!session.remember) {
        // Best-effort server revocation; clearing memory also covers the back/forward cache.
        authRequest('logout').catch(() => {});
        clearAuth('다시 로그인해 주세요.');
      }
    };
    window.addEventListener('pagehide', leave);
    const interval = window.setInterval(expire, 60000);
    window.addEventListener('focus', expire);
    document.addEventListener('visibilitychange', expire);
    return () => { clearTimeout(timer); clearInterval(interval); window.removeEventListener('pagehide', leave); window.removeEventListener('focus', expire); document.removeEventListener('visibilitychange', expire); };
  }, [session]);
  const acceptSession = data => {
    setAccessToken(data.access_token); setSession(data); setMessage(''); setConnectionError('');
  };
  const login = body => authRequest('login', body);
  const logout = async () => {
    // Keep the session visible if revocation fails: do not report a false logout.
    try { await authRequest('logout'); }
    catch (error) { if (error.status !== 401) throw error; }
    notifyLogout('로그아웃했습니다.');
  };
  const updateUser = user => setSession(previous => previous ? { ...previous, user } : previous);
  return <Context.Provider value={{ session, user: session?.user, loading, message, connectionError,
    login, acceptSession, logout, updateUser, retry: () => setRetry(value => value + 1) }}>{children}</Context.Provider>;
}
