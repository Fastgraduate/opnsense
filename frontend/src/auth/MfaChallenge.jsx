import { useState } from 'react';
import { authRequest } from './api';
export function RecoveryCodes({ codes, onDone }) {
  const [saved, setSaved] = useState(false);
  const download = () => {
    const blob = new Blob(['OPNsense Dashboard — 일회용 복구 코드\n각 코드는 한 번만 사용할 수 있습니다.\n\n' + codes.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = 'opnsense-recovery-codes.txt'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return <div className="mfa-recovery"><h3>복구 코드 보관</h3><p className="auth-description">인증 기기를 잃어버렸을 때 사용할 수 있는 일회용 코드입니다. 이 화면을 닫으면 다시 표시되지 않습니다.</p>
    <div className="mfa-code-grid">{codes.map(code => <code key={code}>{code}</code>)}</div>
    <button type="button" className="auth-secondary" onClick={download}>코드 파일 다운로드</button>
    <label className="auth-check"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} /> 복구 코드를 안전한 곳에 보관했습니다.</label>
    <button className="auth-primary" type="button" disabled={!saved} onClick={onDone}>계속</button></div>;
}
export default function MfaChallenge({ challenge, onComplete, onCancel }) {
  const [code, setCode] = useState(''); const [error, setError] = useState(''); const [busy, setBusy] = useState(false); const [result, setResult] = useState(null);
  if (result) return <RecoveryCodes codes={result.recovery_codes} onDone={() => onComplete(result)} />;
  const submit = async e => {
    e.preventDefault(); if (busy) return; setBusy(true); setError('');
    try {
      const data = await authRequest('mfa/complete', { challenge: challenge.challenge, code });
      setCode('');
      if (data.recovery_codes?.length) setResult(data); else onComplete(data);
    } catch (err) { setError(err.message); } finally { setBusy(false); }
  };
  return <div><p className="auth-eyebrow">TWO-FACTOR AUTHENTICATION</p><h2>{challenge.enrollment_required ? '인증 앱 연결' : '2단계 인증'}</h2>
    {challenge.enrollment_required ? <><p className="auth-description">Google Authenticator 또는 Microsoft Authenticator에서 QR을 스캔하고 생성된 6자리 코드를 입력하세요.</p>
      <img className="mfa-qr" src={challenge.setup.qr_data_url} alt="인증 앱 등록 QR 코드" />
      <details className="mfa-manual"><summary>수동 등록 키 보기</summary><code>{challenge.setup.secret}</code></details></> : <p className="auth-description">인증 앱의 6자리 코드 또는 일회용 복구 코드를 입력하세요.</p>}
    {error && <p className="auth-error" role="alert">{error}</p>}
    <form onSubmit={submit}><label className="auth-field"><span>인증 코드</span><input name="otp" value={code} onChange={e => setCode(e.target.value)} autoComplete="one-time-code" autoFocus required maxLength={64} inputMode={challenge.enrollment_required ? 'numeric' : 'text'} /></label>
      <button className="auth-primary" disabled={busy}>{busy ? '확인 중…' : '인증 완료'}</button></form>
    <button className="auth-secondary mfa-back" type="button" disabled={busy} onClick={onCancel}>로그인으로 돌아가기</button>
  </div>;
}
