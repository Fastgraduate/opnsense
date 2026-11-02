export const API_BASE = (import.meta.env.VITE_API_BASE_URL || `${window.location.protocol}//${window.location.hostname}:8000`).replace(/\/$/, '');
let accessToken = null;
let revision = 0;
export function setAccessToken(token) { accessToken = token || null; revision += 1; }
export function clearAuth(message = '') {
  setAccessToken(null);
  window.dispatchEvent(new CustomEvent('dashboard:unauthorized', { detail: message }));
}
export function notifyLogout(message = '') {
  clearAuth(message);
  if ('BroadcastChannel' in window) {
    const channel = new BroadcastChannel('opnsense-auth');
    channel.postMessage('logout'); channel.close();
  }
}
export async function apiFetch(input, options = {}) {
  const url = new URL(input, window.location.href);
  const base = new URL(API_BASE, window.location.href);
  if (url.origin !== base.origin || !url.pathname.startsWith(`${base.pathname.replace(/\/$/, '')}/api/`)) {
    return window.fetch(input, options);
  }
  const started = revision;
  const headers = new Headers(options.headers);
  headers.set('X-Dashboard-Request', '1');
  if (accessToken) headers.set('Authorization', `Bearer ${accessToken}`);
  const response = await window.fetch(input, { ...options, headers, credentials: 'include', cache: 'no-store' });
  if (response.status === 401 && !['/auth/login', '/auth/session', '/auth/mfa/complete'].some(path => url.pathname.endsWith(path)) && started === revision) {
    clearAuth('로그인 시간이 만료되었습니다. 다시 로그인해 주세요.');
  }
  return response;
}
export async function authRequest(path, body, method = 'POST') {
  const response = await apiFetch(`${API_BASE}/api/auth/${path}`, {
    method, headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = typeof data.detail === 'string' ? data.detail : '입력 내용을 확인해 주세요.';
    const error = new Error(message); error.status = response.status; throw error;
  }
  return data;
}
