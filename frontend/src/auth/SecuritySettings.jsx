import { useState } from 'react';
import { authRequest, notifyLogout } from './api';
import { useAuth } from './AuthContext';
import { RecoveryCodes } from './MfaChallenge';
export default function SecuritySettings() {
  const { user } = useAuth(); const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [codes, setCodes] = useState(null); const [reset, setReset] = useState(false);
  const submit = async event => {
    event.preventDefault(); if (busy) return; const form=event.currentTarget; const values=new FormData(form); setBusy(true); setError('');
    try {
      const data = await authRequest(reset ? 'mfa/reset' : 'mfa/recovery-codes', { current_password: values.get('password'), code: values.get('code') }); form.reset();
      if (reset) notifyLogout('인증 앱 연결을 초기화했습니다. 다시 로그인하여 새 기기를 등록하세요.'); else setCodes(data.recovery_codes);
    } catch (err) { setError(err.message); } finally { setBusy(false); }
  };
  return <section className="auth-card"><h3>계정 보안</h3><div className="security-badges"><span>2단계 인증 사용</span><span>{user.role === 'admin' ? '관리자' : '조회 전용'}</span></div>
    {codes ? <RecoveryCodes codes={codes} onDone={() => setCodes(null)} /> : <><p className="auth-description">복구 코드를 새로 발급하거나 인증 기기를 교체할 수 있습니다. 인증 기기 재등록은 모든 로그인 세션을 종료합니다.</p>
    {error && <p className="auth-error" role="alert">{error}</p>}
    <form onSubmit={submit}><fieldset disabled={busy}><label className="auth-field"><span>작업</span><select value={reset ? 'reset' : 'codes'} onChange={e=>setReset(e.target.value === 'reset')}><option value="codes">복구 코드 재발급</option><option value="reset">인증 기기 재등록</option></select></label>
      <label className="auth-field"><span>현재 비밀번호</span><input name="password" type="password" required maxLength={128} autoComplete="current-password" /></label>
      <label className="auth-field"><span>인증 앱 코드 또는 복구 코드</span><input name="code" required maxLength={64} autoComplete="one-time-code" /></label>
      {reset && <label className="auth-check"><input type="checkbox" required /> 기존 인증 연결을 초기화하고 다시 등록하겠습니다.</label>}
      <button className="auth-primary">{busy ? '처리 중…' : reset ? '인증 기기 재등록' : '복구 코드 재발급'}</button></fieldset></form></>}
  </section>;
}
