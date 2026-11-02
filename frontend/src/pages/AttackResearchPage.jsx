import { apiFetch as fetch, API_BASE as AUTH_API_BASE } from '../auth/api';
import { useEffect, useRef, useState } from 'react';
import { twc } from '../lib/twc';
import { researchStyles as rs } from './researchStyles';
const API = AUTH_API_BASE;
const DEFAULT_SQL = 'SELECT timestamp, source_ip, destination_ip, attack_type, main_result_display\nFROM logs\nORDER BY timestamp DESC\nLIMIT 100';
const examples = [
  ['최근 탐지', DEFAULT_SQL],
  ['출발지별 건수', 'SELECT source_ip, COUNT(*) AS count FROM logs GROUP BY source_ip ORDER BY count DESC LIMIT 100'],
  ['SQL Injection', "SELECT * FROM logs WHERE attack_type = 'SQL_Injection' ORDER BY timestamp DESC LIMIT 100"],
  ['IP 검색', "SELECT * FROM logs WHERE source_ip = '192.168.0.6' OR destination_ip = '192.168.0.6' ORDER BY timestamp DESC LIMIT 100"],
];
const cell = value => typeof value === 'object' ? JSON.stringify(value) : String(value ?? '');
export default function AttackResearchPage({ selectedFirewall, mode = 'index' }) {
  const [minutes, setMinutes] = useState(60);
  const [result, setResult] = useState('attack');
  const [query, setQuery] = useState('');
  const [group, setGroup] = useState('attack_type');
  const [sql, setSql] = useState(DEFAULT_SQL);
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const requestRef = useRef(null);
  const id = selectedFirewall?.id;
  async function search() {
    requestRef.current?.abort();
    if (!id) { setData(null); return; }
    const controller = new AbortController(); requestRef.current = controller;
    setBusy(true); setError(''); setSelected(null); setData(null);
    const statement = mode === 'sql' ? sql : `SELECT ${group}, COUNT(*) AS count FROM logs GROUP BY ${group} ORDER BY count DESC LIMIT 100`;
    try {
      const response = await fetch(`${API}/api/firewalls/${id}/security-alerts/search`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal,
        body: JSON.stringify({ minutes: Number(minutes), result, query, sql: statement }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : body.detail?.message || `조회 실패 (${response.status})`);
      if (!controller.signal.aborted) setData(body);
    } catch (e) { if (!controller.signal.aborted) setError(e.message); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  useEffect(() => { search(); return () => requestRef.current?.abort(); }, [id, mode]); // Filters apply on Search.
  function exportCsv() {
    const escape = v => '"' + cell(v).replace(/^[=+@-]/, "'$&").replaceAll('"', '""') + '"';
    const lines = [data.columns, ...data.rows.map(row => data.columns.map(k => row[k]))];
    const url = URL.createObjectURL(new Blob(['\ufeff'+lines.map(r => r.map(escape).join(',')).join('\r\n')], { type:'text/csv;charset=utf-8' }));
    const link = document.createElement('a'); link.href = url; link.download = 'attack-log-search.csv'; link.click(); URL.revokeObjectURL(url);
  }
  return <section className={twc('live-workspace')}>
    <header className={twc('lw-header')}><div><p>ELK · DETECTION RESEARCH</p><h2>{mode === 'sql' ? '공격 로그 SQL 검색' : '공격 로그 인덱싱'}</h2></div>
      <div className={twc('lw-tools')}><button className={twc('ui-control-btn')} disabled={!id || busy} onClick={search}>{busy ? '조회 중…' : '검색'}</button><button className={twc('ui-control-btn')} disabled={!data?.rows?.length} onClick={exportCsv}>CSV</button></div>
    </header>
    {error && <div className={twc('lw-error')} role="alert">{error}</div>}
    {!id && <p>방화벽을 먼저 선택하세요.</p>}
    <div className="grid min-h-0 flex-1 grid-cols-[minmax(240px,320px)_minmax(0,1fr)] gap-3 max-[900px]:grid-cols-1 overflow-auto">
      <aside className={twc('lw-box p-5 !overflow-y-auto')}>
        <div className="mb-4"><p className="text-[10px] font-black tracking-widest text-violet-500">SEARCH FILTERS</p><h3 className="mt-1 text-base font-extrabold text-slate-800 dark:text-white">{mode === 'sql' ? 'SQL 검색 조건' : '로그 집계 조건'}</h3></div><p className={rs.intro}>{mode === 'sql' ? '탐지 로그를 SQL로 검색하고 결과를 확인하세요.' : '탐지된 로그를 공격 유형과 IP별로 집계합니다.'}</p>
        <label className={rs.field}>조회 기간<select className={rs.control} value={minutes} onChange={e=>setMinutes(e.target.value)}>{[[5,'5분'],[60,'1시간'],[1440,'24시간'],[10080,'7일']].map(([v,l])=><option key={v} value={v}>{l}</option>)}</select></label>
        <label className={rs.field}>탐지 결과<select className={rs.control} value={result} onChange={e=>setResult(e.target.value)}><option value="attack">공격</option><option value="all">전체</option><option value="normal">정상</option></select></label>
        <label className={rs.field}>로그 검색<input className={rs.control} value={query} onChange={e=>setQuery(e.target.value)} placeholder="IP / 탐지 내용" /></label>
        {mode === 'index' ? <label className={rs.field}>집계 기준<select className={rs.control} value={group} onChange={e=>setGroup(e.target.value)}>{['attack_type','source_ip','destination_ip','protocol','action'].map(k=><option key={k} value={k}>{{attack_type:'공격 유형',source_ip:'출발지 IP',destination_ip:'목적지 IP',protocol:'프로토콜',action:'탐지 동작'}[k]}</option>)}</select></label> : <><label className={rs.field}>SQL<textarea spellCheck={false} className={rs.editor} value={sql} onChange={e=>setSql(e.target.value)}/></label><div className="flex flex-wrap gap-2 mt-3">{examples.map(([label,text])=><button key={label} className={twc('ui-control-btn')} onClick={()=>setSql(text)}>{label}</button>)}</div><p className="text-xs leading-5 mt-3">읽기 전용 SELECT · WHERE · GROUP BY · ORDER BY · LIMIT. 테이블: logs. 예시의 IP를 실제 검색 주소로 바꾸세요.</p></>}
        <p className={rs.note}>조회 시점 기준 최신 최대 5,000건에서 집계·SQL을 실행합니다. SQL 결과는 최대 500행입니다. 범위를 좁혀 검색하면 누락을 줄일 수 있습니다.</p>
      </aside>
      <div className={twc('lw-box flex min-h-0 flex-col overflow-hidden')}>
        <div className={rs.meta} role="status">{busy ? '탐지 로그를 조회하고 있습니다…' : data ? `조회 로그 ${data.scanned}건 · 결과 ${data.rows.length}행 · ${data.index || '설정된 공격 탐지 인덱스'}` : '검색 결과'}</div>
        {data?.source_truncated && <p className="p-3 text-amber-600 text-xs">원본 로그가 5,000건을 초과해 일부만 검색했습니다. 기간이나 로그 검색 조건을 좁혀주세요.</p>}
        {data?.result_truncated && <p className="p-3 text-amber-600 text-xs">결과가 500행을 초과해 앞부분만 표시합니다.</p>}
        <div className="min-h-0 flex-1 overflow-auto"><table className="w-full text-left text-xs"><thead className={rs.head}><tr>{data?.columns.map(k=><th className="p-3 whitespace-nowrap" key={k}>{k}</th>)}</tr></thead><tbody>{data?.rows.map((r,i)=><tr key={i} tabIndex={0} onClick={()=>setSelected(r)} onKeyDown={e=>e.key==='Enter'&&setSelected(r)} className={rs.row}>{data.columns.map(k=><td className="p-3 max-w-80 truncate" key={k} title={cell(r[k])}>{cell(r[k]) || '—'}</td>)}</tr>)}</tbody></table>{data && !data.rows.length && <p className="p-8 text-center">조건에 맞는 탐지 로그가 없습니다.</p>}</div>
        {selected && <div className="max-h-60 overflow-auto border-t border-[var(--border)] p-3"><button className={twc('ui-control-btn')} onClick={()=>setSelected(null)}>상세 닫기</button><pre className="text-xs whitespace-pre-wrap break-all mt-2">{JSON.stringify(selected,null,2)}</pre></div>}
      </div>
    </div>
  </section>;
}
