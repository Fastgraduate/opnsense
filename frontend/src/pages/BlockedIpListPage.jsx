import { useCanManage } from '../auth/AuthContext';
import { apiFetch as fetch, API_BASE as AUTH_API_BASE } from '../auth/api';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { twc } from '../lib/twc';
import { useModal } from '../components/ui/modalContext';

const API_BASE = AUTH_API_BASE;
const TIME_ZONE = 'Asia/Seoul';

function formatBlockedAt(value) {
  if (!value) return '-';
  const date = new Date(Number(value) * 1000);
  if (Number.isNaN(date.getTime())) return '-';
  return new Intl.DateTimeFormat('ko-KR', {
    timeZone: TIME_ZONE,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false,
  }).format(date).replace(/\. /g, '.').replace(/\.$/, '');
}

async function readJson(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = data?.detail;
    const message = typeof detail === 'string' ? detail : detail?.message || data?.message || `요청 실패 (${response.status})`;
    throw new Error(message);
  }
  return data;
}

export default function BlockedIpListPage({ selectedFirewall, onAppLog }) {
  const canManage = useCanManage();
  const { confirm, notify } = useModal();
  const [rows, setRows] = useState([]);
  const [alias, setAlias] = useState('blocked_attackers');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [unblocking, setUnblocking] = useState('');
  const firewallId = selectedFirewall?.id;
  const targetRef = useRef(firewallId);
  const generation = useRef(0);
  targetRef.current = firewallId;
  const appliedCount = rows.filter(row => row.status === 'blocked').length;

  const load = useCallback(async (silent = false) => {
    if (!firewallId) {
      setRows([]);
      return;
    }
    const version = ++generation.current;
    if (!silent) setLoading(true);
    try {
      const data = await readJson(await fetch(`${API_BASE}/api/firewalls/${firewallId}/manual-blocks`, { cache: 'no-store' }));
      if (targetRef.current !== firewallId || version !== generation.current) return;
      setRows(Array.isArray(data?.rows) ? data.rows : []);
      setAlias(data?.alias || 'blocked_attackers');
      setError('');
    } catch (err) {
      if (targetRef.current !== firewallId || version !== generation.current) return;
      setRows([]);
      setError(err.message || '차단 목록을 불러오지 못했습니다.');
      onAppLog?.('ERROR', `차단 IP 목록 조회 실패: ${err.message || err}`, { dedupeKey: `manual-block-list:${firewallId}:${err.message}`, dedupeMs: 30000 });
    } finally {
      if (targetRef.current === firewallId && version === generation.current) setLoading(false);
    }
  }, [firewallId, onAppLog]);

  useEffect(() => {
    setRows([]);
    setError('');
    load();
    if (!firewallId) return undefined;
    const timer = window.setInterval(() => load(true), 15000);
    return () => window.clearInterval(timer);
  }, [firewallId, load]);

  const newest = useMemo(() => rows[0]?.created_at ? formatBlockedAt(rows[0].created_at) : '-', [rows]);

  const unblock = async row => {
    if (!firewallId || !row?.ip || unblocking) return;
    const accepted = await confirm({
      tone: 'warning',
      title: '차단 해제',
      message: `${row.ip}의 차단을 해제할까요?`,
      detail: `${row.alias || alias} Alias에서 해당 IP를 제거하고 방화벽 변경사항을 적용합니다.`,
      confirmText: '차단 해제',
      cancelText: '취소',
    });
    if (!accepted || targetRef.current !== firewallId) return;
    generation.current += 1;

    setUnblocking(row.ip);
    try {
      const data = await readJson(await fetch(`${API_BASE}/api/firewalls/${firewallId}/manual-blocks/${encodeURIComponent(row.ip)}`, { method: 'DELETE' }));
      if (targetRef.current === firewallId) {
        generation.current += 1;
        setRows(previous => previous.filter(item => item.ip !== row.ip));
      }
      onAppLog?.('SUCCESS', `차단 해제 완료: ${row.ip}`);
      await notify({ tone: 'success', title: '차단 해제 완료', message: data?.message || `${row.ip} 차단을 해제했습니다.`, detail: data?.audit_warning || '' });
    } catch (err) {
      onAppLog?.('ERROR', `차단 해제 실패: ${row.ip} · ${err.message || err}`);
      await notify({ tone: 'danger', title: '차단 해제 실패', message: err.message || '차단 해제 요청에 실패했습니다.' });
    } finally {
      setUnblocking('');
    }
  };

  return <section className={twc("live-workspace") }>
    <header className={twc("lw-header") }>
      <div>
        <p>LIVE · RESPONSE</p>
        <h2>수동 차단 목록</h2>
      </div>
      <div className={twc("lw-tools") }>
        <span className={twc("ui-meta-chip")} role="status">{loading ? '조회 중' : `${appliedCount}개 적용 확인`}</span>
        <button type="button" className={twc("ui-control-btn")} onClick={() => load()} disabled={!firewallId || loading}>새로고침</button>
      </div>
    </header>

    {error ? <div className={twc("lw-error") } role="alert">{error}</div> : null}

    <div className={twc("grid min-h-0 flex-1 grid-cols-[minmax(220px,280px)_minmax(0,1fr)] gap-3 max-[900px]:grid-cols-1") }>
      <aside className={twc("lw-box p-5 max-[900px]:p-4") }>
        <p className={twc("m-0 text-[10px] font-black uppercase tracking-[.18em] text-violet-600 dark:text-violet-300")}>BLOCK SUMMARY</p>
        <h3 className={twc("mt-1 text-lg font-black text-slate-950 dark:text-white")}>수동 차단 현황</h3>
        <div className={twc("mt-4 grid gap-3") }>
          <div className={twc("rounded-2xl border border-[var(--border)] bg-[var(--input-bg)] p-4") }><span className={twc("text-[11px] font-bold text-[var(--text-muted)]")}>현재 차단</span><strong className={twc("mt-1 block text-2xl font-black text-[var(--text-main)]")}>{appliedCount}개</strong></div>
          <div className={twc("rounded-2xl border border-[var(--border)] bg-[var(--input-bg)] p-4") }><span className={twc("text-[11px] font-bold text-[var(--text-muted)]")}>Alias</span><strong className={twc("mt-1 block break-all text-sm font-black text-[var(--text-main)]")}>{alias}</strong></div>
          <div className={twc("rounded-2xl border border-[var(--border)] bg-[var(--input-bg)] p-4") }><span className={twc("text-[11px] font-bold text-[var(--text-muted)]")}>최근 차단</span><strong className={twc("mt-1 block text-xs font-black leading-5 text-[var(--text-main)]")}>{newest}</strong></div>
        </div>
        <p className={twc("mt-4 text-[10px] font-semibold leading-5 text-[var(--text-muted)]")}>OPNsense Alias와 규칙을 직접 조회합니다. 적용 미확인은 공격 로그에서 차단을 재적용하세요. 차단 해제 시 OPNsense Alias에서 주소를 제거하고 방화벽 변경사항을 적용합니다.</p>
      </aside>

      <div className={twc("lw-box min-h-0 overflow-hidden") }>
        <div className={twc("flex items-center justify-between gap-3 border-b border-[var(--border)] px-5 py-4") }>
          <div><p className={twc("m-0 text-[10px] font-black uppercase tracking-[.16em] text-violet-600 dark:text-violet-300")}>BLOCKED ADDRESSES</p><h3 className={twc("m-0 mt-1 text-base font-black text-[var(--text-main)]")}>차단한 IP</h3></div>
          <span className={twc("rounded-full border border-[var(--border)] bg-[var(--input-bg)] px-3 py-1.5 text-xs font-black text-[var(--text-muted)]")}>{rows.length}개</span>
        </div>
        <div className={twc("h-full min-h-0 overflow-auto") }>
          <table className={twc("w-full min-w-[720px] border-collapse text-left text-xs") }>
            <thead className={twc("sticky top-0 z-10 bg-[var(--surface-strong)] text-[var(--text-muted)]") }>
              <tr><th className={twc("px-5 py-3 font-black")}>IP 주소</th><th className={twc("px-4 py-3 font-black")}>Alias</th><th className={twc("px-4 py-3 font-black")}>차단 시간</th><th className={twc("px-4 py-3 font-black")}>상태</th><th className={twc("px-5 py-3 text-right font-black")}>관리</th></tr>
            </thead>
            <tbody>
              {!loading && rows.length === 0 ? <tr><td colSpan="5" className={twc("px-5 py-16 text-center font-bold text-[var(--text-muted)]")}>현재 수동 차단된 IP가 없습니다.</td></tr> : rows.map(row => <tr key={row.ip} className={twc("border-t border-[var(--border)] text-[var(--text-main)]") }>
                <td className={twc("px-5 py-4 font-black")}>{row.ip}</td>
                <td className={twc("px-4 py-4 font-semibold text-[var(--text-muted)]")}>{row.alias || alias}</td>
                <td className={twc("px-4 py-4 font-semibold")}>{formatBlockedAt(row.created_at)}</td>
                <td className={twc("px-4 py-4") }><span className={twc("inline-flex rounded-full border border-rose-200 bg-rose-50 px-2.5 py-1 text-[10px] font-black text-rose-600 dark:border-rose-400/20 dark:bg-rose-400/10 dark:text-rose-300")}>{row.status === 'blocked' ? '적용 확인' : '적용 미확인'}</span></td>
                <td className={twc("px-5 py-4 text-right") }><button type="button" className={twc("ui-control-btn ui-control-btn-danger") } disabled={!canManage || Boolean(unblocking)} onClick={() => unblock(row)}>{unblocking === row.ip ? '해제 중…' : '차단 해제'}</button></td>
              </tr>)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>;
}
