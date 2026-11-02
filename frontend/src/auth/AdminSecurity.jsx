import { useEffect, useState } from 'react';
import { authRequest, notifyLogout } from './api';
import { useAuth } from './AuthContext';
export default function AdminSecurity() {
  const { user } = useAuth(); const [users, setUsers] = useState([]); const [logs, setLogs] = useState([]); const [cursor,setCursor]=useState(0); const [hasMore,setHasMore]=useState(false); const [busy,setBusy]=useState(false); const [error,setError]=useState(''); const [message,setMessage]=useState('');
  const load = async (before=0) => {
    setBusy(true);setError('');
    try { const [people,audit]=await Promise.all([authRequest('admin/users',null,'GET'),authRequest(`admin/audit?before_id=${before}`,null,'GET')]);setUsers(people.rows);setLogs(audit.rows);setCursor(audit.next_before_id);setHasMore(audit.has_more); }
    catch(err){setError(err.message);}finally{setBusy(false);}
  };
  useEffect(()=>{load();},[]);
  const submit=async event=>{
    event.preventDefault();if(busy)return;const form=event.currentTarget;const values=new FormData(form);const id=Number(values.get('user_id'));setBusy(true);setError('');setMessage('');
    try {await authRequest(`admin/users/${id}/role`,{role:values.get('role'),current_password:values.get('password'),code:values.get('code')},'PUT');form.reset();if(id===user.id){notifyLogout('권한이 변경되었습니다. 다시 로그인하세요.');return;}setMessage('권한을 변경하고 대상 사용자의 기존 세션을 종료했습니다.');await load();}
    catch(err){setError(err.message);}finally{setBusy(false);}
  };
  return <section className="auth-card admin-security"><h3>사용자 권한 및 감사 로그</h3>
    {error&&<p className="auth-error" role="alert">{error}</p>}{message&&<p className="auth-success" role="status">{message}</p>}
    <div className="security-user-list">{users.map(person=><div key={person.id}><strong>{person.name} <small>({person.username})</small></strong><span>{person.role==='admin'?'관리자':'조회 전용'} · {person.mfa_enabled?'2단계 인증 등록':'등록 대기'}</span></div>)}</div>
    <details><summary>사용자 권한 변경</summary><form onSubmit={submit}><fieldset disabled={busy}>
      <label className="auth-field"><span>사용자</span><select name="user_id" required defaultValue=""><option value="" disabled>계정 선택</option>{users.map(person=><option key={person.id} value={person.id}>{person.name} ({person.username})</option>)}</select></label>
      <label className="auth-field"><span>변경 권한</span><select name="role"><option value="viewer">조회 전용</option><option value="admin">관리자</option></select></label>
      <label className="auth-field"><span>관리자 현재 비밀번호</span><input name="password" type="password" required maxLength={128} autoComplete="current-password" /></label>
      <label className="auth-field"><span>관리자 인증 앱 코드 또는 복구 코드</span><input name="code" required maxLength={64} autoComplete="one-time-code" /></label>
      <button className="auth-primary">권한 변경</button></fieldset></form></details>
    <div className="audit-heading"><h4>감사 로그</h4><button type="button" className="auth-secondary" disabled={busy} onClick={()=>load()}>최신 조회</button></div>
    <p className="auth-description">API 처리 결과를 기록합니다. HTTP 성공이 실제 장비 적용 성공을 의미하지는 않습니다.</p>
    <div className="audit-scroll"><table><thead><tr><th>시간</th><th>사용자 ID</th><th>작업</th><th>요청 경로</th><th>HTTP</th><th>접속 IP</th></tr></thead><tbody>{logs.map(log=><tr key={log.id}><td>{new Date(log.at*1000).toLocaleString('ko-KR')}</td><td>{log.actor_id??'미인증'}</td><td>{log.action}</td><td>{log.method} {log.route}</td><td>{log.status}</td><td>{log.client_ip}</td></tr>)}</tbody></table></div>
    <button type="button" className="auth-secondary mfa-back" disabled={busy||!hasMore} onClick={()=>load(cursor)}>이전 기록</button>
  </section>;
}
