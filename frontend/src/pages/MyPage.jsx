import SecuritySettings from '../auth/SecuritySettings';
import AdminSecurity from '../auth/AdminSecurity';
import { useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { authRequest, notifyLogout } from '../auth/api';
import { Field } from '../auth/AuthGate';
export default function MyPage() {
  const { user, updateUser } = useAuth();
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const submit = async (event, kind) => {
    event.preventDefault(); if (busy) return;
    const form = event.currentTarget, values = new FormData(form);
    setError(''); setSuccess('');
    if (kind === 'password' && values.get('new_password') !== values.get('confirm_password')) { setError('새 비밀번호 확인이 일치하지 않습니다.'); return; }
    setBusy(kind);
    try {
      if (kind === 'profile') {
        updateUser(await authRequest('me', { name: values.get('name'), email: values.get('email') }, 'PUT'));
        setSuccess('개인정보를 저장했습니다.');
      } else {
        await authRequest('password', { current_password: values.get('current_password'), new_password: values.get('new_password'), code: values.get('code') }, 'PUT');
        form.reset(); notifyLogout('비밀번호를 변경했습니다. 새 비밀번호로 다시 로그인해 주세요.');
      }
    } catch (err) { setError(err.message); }
    finally { setBusy(''); }
  };
  return <section className="account-page">
    <div className="account-heading"><div><p className="auth-eyebrow">MY ACCOUNT</p><h2>{user.name}님의 계정</h2><p>개인정보와 로그인 정보를 관리하세요.</p></div></div>
    {error && <p className="auth-error" role="alert">{error}</p>}{success && <p className="auth-success" role="status">{success}</p>}
    <div className="account-grid">
      <section className="auth-card"><h3>개인정보</h3><form onSubmit={event => submit(event, 'profile')}><fieldset disabled={!!busy}>
        <Field label="아이디" value={user.username} readOnly /><Field label="이름" name="name" defaultValue={user.name} required maxLength={50} autoComplete="name" /><Field label="이메일" name="email" type="email" defaultValue={user.email} required maxLength={254} autoComplete="email" />
        <button className="auth-primary">{busy === 'profile' ? '저장 중…' : '변경사항 저장'}</button>
      </fieldset></form></section>
      <section className="auth-card"><h3>비밀번호 변경</h3><p className="auth-description">변경하면 모든 기기에서 로그아웃됩니다.</p><form onSubmit={event => submit(event, 'password')}><fieldset disabled={!!busy}>
        <Field label="현재 비밀번호" name="current_password" type="password" required maxLength={128} autoComplete="current-password" /><Field label="새 비밀번호" name="new_password" type="password" required minLength={10} maxLength={128} autoComplete="new-password" placeholder="10자 이상 입력하세요" /><Field label="새 비밀번호 확인" name="confirm_password" type="password" required minLength={10} maxLength={128} autoComplete="new-password" />
        <Field label="인증 앱 코드 또는 복구 코드" name="code" required maxLength={64} autoComplete="one-time-code" />
        <button className="auth-primary">{busy === 'password' ? '변경 중…' : '비밀번호 변경'}</button>
      </fieldset></form></section>
      <SecuritySettings />
      {user.role === 'admin' && <AdminSecurity />}
    </div>
  </section>;
}
