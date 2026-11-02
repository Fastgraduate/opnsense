import MfaChallenge from './MfaChallenge';
import { useState } from 'react';
import { useAuth } from './AuthContext';
import { authRequest } from './api';
import './auth.css';
function Field({ label, ...props }) {
  return <label className="auth-field"><span>{label}</span><input {...props} /></label>;
}
export { Field };
export default function AuthGate({ children }) {
  const { user, loading, message, connectionError, retry, login, acceptSession } = useAuth();
  const [challenge, setChallenge] = useState(null);
  const [register, setRegister] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  if (loading) return <main className="auth-screen"><div className="auth-card" role="status">로그인 상태를 확인하고 있습니다…</div></main>;
  if (user) return children;
  const switchMode = () => { setRegister(value => !value); setError(''); setSuccess(''); };
  const submit = async event => {
    event.preventDefault(); if (busy) return;
    const form = new FormData(event.currentTarget);
    setError(''); setSuccess('');
    if (register && form.get('password') !== form.get('confirm_password')) { setError('비밀번호 확인이 일치하지 않습니다.'); return; }
    setBusy(true);
    try {
      if (register) {
        await authRequest('register', Object.fromEntries(['username', 'name', 'email', 'password', 'registration_code'].map(key => [key, form.get(key)])));
        setRegister(false); setSuccess('회원가입이 완료되었습니다. 새 계정으로 로그인해 주세요.');
      } else {
        const data = await login({ username: form.get('username'), password: form.get('password'), remember: form.get('remember') === 'on' });
        setChallenge(data);
      }
    } catch (err) { setError(err.message === 'Failed to fetch' ? '서버에 연결할 수 없습니다. 백엔드 실행 상태를 확인해 주세요.' : err.message); }
    finally { setBusy(false); }
  };
  return <main className="auth-screen">
    <section className="auth-intro" aria-label="서비스 소개">
      <div className="auth-brand"><span className="auth-shield">◈</span> OPNsense <span>Security Intelligence</span></div>
      <p className="auth-eyebrow">SECURITY OPERATIONS</p>
      <h1>안전한 관제의 시작,<br />인증된 접근부터.</h1>
      <p>위협 탐지부터 정책 대응까지.<br />팀의 보안 현황을 한곳에서 확인하세요.</p>
      <div className="auth-features"><span>실시간 공격 탐지</span><span>방화벽 정책 관리</span><span>IP 차단 대응</span></div>
    </section>
    <section className="auth-card">
      {challenge ? <MfaChallenge challenge={challenge} onComplete={data => { setChallenge(null); acceptSession(data); }} onCancel={() => { setChallenge(null); setError(''); }} /> : <>
      <p className="auth-eyebrow">{register ? 'CREATE ACCOUNT' : 'WELCOME BACK'}</p>
      <h2>{register ? '회원가입' : '로그인'}</h2>
      <p className="auth-description">{register ? '운영자에게 받은 가입 코드로 관제 계정을 만드세요.' : '계정으로 로그인하여 보안 관제를 시작하세요.'}</p>
      {connectionError && <div className="auth-notice" role="alert">{connectionError} <button type="button" onClick={retry}>다시 연결</button></div>}
      {error && <p className="auth-error" role="alert">{error}</p>}
      {success && <p className="auth-success" role="status">{success}</p>}
      {!success && !register && message && !connectionError && <p className="auth-notice" role="status">{message}</p>}
      <form onSubmit={submit} key={register ? 'register' : 'login'}>
        <fieldset disabled={busy}>
          <Field label="아이디" name="username" autoComplete="username" required minLength={register ? 4 : 1} maxLength={32} pattern={register ? '[a-z0-9_]{4,32}' : undefined} placeholder={register ? '영문 소문자·숫자·밑줄 4~32자' : '아이디를 입력하세요'} />
          {register && <div className="auth-two"><Field label="이름" name="name" required maxLength={50} autoComplete="name" /><Field label="이메일" name="email" type="email" required maxLength={254} autoComplete="email" /></div>}
          <Field label="비밀번호" name="password" type="password" autoComplete={register ? 'new-password' : 'current-password'} required minLength={register ? 10 : 1} maxLength={128} placeholder={register ? '10자 이상 입력하세요' : '비밀번호를 입력하세요'} />
          {register && <><Field label="비밀번호 확인" name="confirm_password" type="password" required minLength={10} maxLength={128} autoComplete="new-password" /><Field label="가입 코드" name="registration_code" type="password" required maxLength={256} autoComplete="off" placeholder="운영자에게 받은 코드" /></>}
          {!register && <><label className="auth-check"><input type="checkbox" name="remember" /> 자동로그인</label></>}
          <button className="auth-primary" type="submit">{busy ? '처리 중…' : register ? '계정 만들기' : '로그인'}</button>
        </fieldset>
      </form>
      <p className="auth-switch">{register ? '이미 계정이 있으신가요?' : '아직 계정이 없으신가요?'} <button type="button" disabled={busy} onClick={switchMode}>{register ? '로그인' : '회원가입'}</button></p>
      </>}
    </section>
  </main>;
}
