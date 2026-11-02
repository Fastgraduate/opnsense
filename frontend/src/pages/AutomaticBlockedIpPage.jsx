import { useCanManage } from '../auth/AuthContext';
import { apiFetch as fetch, API_BASE as AUTH_API_BASE } from '../auth/api';
import { useEffect, useRef, useState } from 'react';
import { useModal } from '../components/ui/modalContext';
import { twc } from '../lib/twc';
import { researchStyles as rs } from './researchStyles';
const API = AUTH_API_BASE;
export default function AutomaticBlockedIpPage({ selectedFirewall }) {
  const canManage = useCanManage();
  const [data, setData] = useState(null), [error, setError] = useState(''), [busy, setBusy] = useState(false), [refresh,setRefresh] = useState(0);
  const id = selectedFirewall?.id;
  const { confirm, notify } = useModal();
  const [ipInput, setIpInput] = useState('');
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [changing, setChanging] = useState(false);
  const mutation = useRef(false), epoch = useRef(0), target = useRef(id);
  target.current = id;
  useEffect(() => { setIpInput(''); setAllowPrivate(false); }, [id]);
  async function change(ip, remove = false) {
    if (!id || mutation.current || !ip.trim()) return;
    const firewall = id, address = ip.trim(), force = allowPrivate;
    mutation.current = true; epoch.current += 1; setChanging(true);
    try {
      const accepted = await confirm({ tone: remove ? 'warning' : 'danger',
        title: remove ? '자동 목록에서 차단 해제' : '자동 차단 Alias에 IP 추가',
        message: `${address} ${remove ? '차단을 해제할까요?' : '통신을 차단할까요?'}`,
        detail: remove ? '자동 차단 엔진이 다시 탐지하면 재등록할 수 있습니다.' : '출발지·목적지 차단 규칙을 적용하고 해당 IP의 기존 연결을 종료합니다.',
        confirmText: remove ? '차단 해제' : '추가 및 차단' });
      if (!accepted || target.current !== firewall) return;
      const response = await fetch(`${API}/api/firewalls/${firewall}/automatic-blocks${remove ? '/' + encodeURIComponent(address) : ''}`, {
        method: remove ? 'DELETE' : 'POST', headers: { 'Content-Type': 'application/json' },
        ...(remove ? {} : { body: JSON.stringify({ source_ip: address, force }) }),
      });
      const body = await response.json();
      if (!response.ok || !body.ok) throw new Error(typeof body.detail === 'string' ? body.detail : body.detail?.message || '변경 적용 실패');
      if (target.current === firewall) { setIpInput(''); setAllowPrivate(false); }
      await notify({ tone: 'success', title: remove ? '차단 해제 완료' : '차단 적용 완료', message: body.message,
        detail: [body.state_warning, body.engine_notice].filter(Boolean).join('\n') });
    } catch (e) { await notify({ tone: 'danger', title: '차단 목록 변경 실패', message: e.message }); }
    finally { mutation.current = false; epoch.current += 1; setChanging(false); setRefresh(v => v + 1); }
  }
  useEffect(()=>{
    const controller = new AbortController(); let loading=false;
    setData(null); setError('');
    async function load() {
      if (!id || loading || mutation.current) return;
      const version = epoch.current;
      loading=true; setBusy(true);
      try {
        const response=await fetch(`${API}/api/firewalls/${id}/automatic-blocks`,{signal:controller.signal,cache:'no-store'});
        const body=await response.json();
        if(!response.ok) throw new Error(typeof body.detail==='string'?body.detail:body.detail?.message||'자동 목록 조회 실패');
        if(!controller.signal.aborted && version === epoch.current){setData(body);setError('');}
      }catch(e){if(!controller.signal.aborted){setError(e.message);setData(null);}}
      finally{loading=false;if(!controller.signal.aborted)setBusy(false);}
    }
    load();const timer=setInterval(load,15000);
    return ()=>{controller.abort();clearInterval(timer);};
  },[id,refresh]);
  return <section className={twc('live-workspace')}><header className={twc('lw-header')}><div><p>AUTOMATIC · RESPONSE</p><h2>자동 차단 목록</h2></div><button className={twc('ui-control-btn')} disabled={!id||busy||changing} onClick={()=>setRefresh(v=>v+1)}>{busy?'조회 중…':'새로고침'}</button></header>
    {error&&<div role="alert" className={twc('lw-error')}>{error}</div>}
    {data?.available && <form onSubmit={e=>{e.preventDefault();change(ipInput);}} className="flex shrink-0 flex-wrap items-end gap-3 rounded-2xl border border-violet-200/60 bg-white/60 p-4 dark:border-violet-400/20 dark:bg-slate-900/60">
      <label className="min-w-52 flex-1 text-xs font-bold text-slate-600 dark:text-slate-300">추가할 IP 주소<input aria-label="추가할 IP 주소" className={rs.control} value={ipInput} onChange={e=>setIpInput(e.target.value)} placeholder="예: 192.168.0.6" disabled={!canManage || changing || !data.editable} required /></label>
      <label className="flex items-center gap-2 pb-3 text-xs text-slate-600 dark:text-slate-300"><input type="checkbox" checked={allowPrivate} onChange={e=>setAllowPrivate(e.target.checked)} disabled={!canManage || changing || !data.editable}/>실습망 사설 IP 허용</label>
      <button type="submit" className={twc('ui-control-btn ui-control-btn-danger')} disabled={!canManage || changing || !data.editable || !ipInput.trim()}>{changing ? '처리 중…' : 'IP 추가 및 차단'}</button>
      {!data.editable && <p className="w-full text-xs text-amber-600">직접 편집은 단일 IP로 구성된 활성 Host Alias에서 지원합니다.</p>}
    </form>}
    <div className={twc('lw-box flex min-h-0 flex-1 flex-col overflow-hidden')}>{(!id || !data?.available) ? <div className="flex min-h-72 flex-1 flex-col items-center justify-center px-6 py-12 text-center" role="status">
      <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-3xl border border-violet-200 bg-violet-100/60 text-violet-500 shadow-sm dark:border-violet-400/20 dark:bg-violet-400/10"><svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" aria-hidden="true"><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z"/><path d="M12 8v5m0 3v.2"/></svg></div>
      <span className="mb-3 rounded-full border border-violet-200 bg-violet-50 px-3 py-1 text-[10px] font-bold text-violet-600 dark:border-violet-400/20 dark:bg-violet-400/10 dark:text-violet-300">{error ? '조회 실패' : !id ? '방화벽 미선택' : busy ? '조회 중' : '연결 대기'}</span>
      <h3 className="text-lg font-extrabold text-slate-800 dark:text-white">{error ? '목록을 불러오지 못했습니다' : !id ? '방화벽을 선택하세요' : busy ? '자동 차단 현황 확인 중' : '자동 차단 목록이 아직 연결되지 않았습니다'}</h3>
      <p className="mt-3 max-w-md text-xs leading-6 text-slate-500 dark:text-slate-400">{error ? '위 오류 내용을 확인한 뒤 새로고침하세요.' : !id ? '방화벽 선택 후 차단 현황을 확인할 수 있습니다.' : data?.message || '잠시만 기다려주세요.'}</p>
      </div> : <p className={rs.meta} role="status">{data.message}</p>}
      {data?.available && <><p className="px-4 pb-3 text-xs">Alias: {data.alias} · {data.rows.length}개</p><div className="min-h-0 flex-1 overflow-auto"><table className="w-full text-left text-sm"><thead className={rs.head}><tr><th className="p-4">IP / 네트워크</th><th>Alias</th><th>상태</th><th className="p-4 text-right">관리</th></tr></thead><tbody>{data.rows.map(r=><tr key={r.ip} className={rs.row}><td className="p-4">{r.ip}</td><td>{r.alias}</td><td><span className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[10px] font-bold text-emerald-700 dark:border-emerald-400/20 dark:bg-emerald-400/10 dark:text-emerald-300">테이블 등록 확인</span></td><td className="p-4 text-right"><button type="button" className={twc('ui-control-btn ui-control-btn-danger')} disabled={!canManage || changing || !r.can_remove} onClick={()=>change(r.ip,true)} title={r.can_remove ? '해당 IP만 차단 해제' : 'Alias 원본에서 관리하는 항목입니다'}>차단 해제</button></td></tr>)}</tbody></table>{!data.rows.length&&<p className="p-8 text-center">자동 차단 Alias에 등록된 주소가 없습니다.</p>}</div></>}
    </div></section>;
}
