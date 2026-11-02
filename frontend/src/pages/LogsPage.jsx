import { twc } from "../lib/twc";
import { useMemo, useState } from 'react';

const LOG_PAGE_SIZE = 30;
const LEVEL_META = {
  INFO: {
    label: 'INFO',
    accent: 'text-sky-600 dark:text-sky-300',
    chip: 'bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-200',
    dot: 'bg-sky-500'
  },
  SUCCESS: {
    label: 'SUCCESS',
    accent: 'text-emerald-600 dark:text-emerald-300',
    chip: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-200',
    dot: 'bg-emerald-500'
  },
  WARN: {
    label: 'WARN',
    accent: 'text-amber-600 dark:text-amber-300',
    chip: 'bg-amber-100 text-amber-700 dark:bg-amber-500/15 dark:text-amber-200',
    dot: 'bg-amber-500'
  },
  ERROR: {
    label: 'ERROR',
    accent: 'text-rose-600 dark:text-rose-300',
    chip: 'bg-rose-100 text-rose-700 dark:bg-rose-500/15 dark:text-rose-200',
    dot: 'bg-rose-500'
  }
};

function LogsPage({
  logs = [],
  setLogs
}) {
  const [currentPage, setCurrentPage] = useState(1);

  const normalizeLevel = level => {
    const value = String(level || 'INFO').toUpperCase();
    if (value === 'ERROR') return 'ERROR';
    if (value === 'WARN' || value === 'WARNING') return 'WARN';
    if (value === 'SUCCESS') return 'SUCCESS';
    return 'INFO';
  };

  const totalPages = Math.max(1, Math.ceil(logs.length / LOG_PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);

  const pagedLogs = useMemo(() => {
    const start = (safePage - 1) * LOG_PAGE_SIZE;
    return logs.slice(start, start + LOG_PAGE_SIZE);
  }, [logs, safePage]);

  const stats = useMemo(() => {
    const counts = {
      INFO: 0,
      SUCCESS: 0,
      WARN: 0,
      ERROR: 0
    };
    logs.forEach(log => {
      counts[normalizeLevel(log.level)] += 1;
    });
    return counts;
  }, [logs]);

  const lastLogTime = logs[0]?.time || logs[logs.length - 1]?.time || '-';

  const handleClearLogs = () => {
    setLogs([]);
    setCurrentPage(1);
  };

  const pageNumbers = Array.from({
    length: totalPages
  }, (_, index) => index + 1).filter(page => {
    if (totalPages <= 7) return true;
    if (page === 1 || page === totalPages) return true;
    return Math.abs(page - safePage) <= 2;
  });

  const statCards = [{
    key: 'INFO',
    title: '일반 로그',
    description: '상태 및 처리 정보'
  }, {
    key: 'SUCCESS',
    title: '성공 로그',
    description: '요청 완료 및 적용 성공'
  }, {
    key: 'WARN',
    title: '경고 로그',
    description: '주의가 필요한 이벤트'
  }, {
    key: 'ERROR',
    title: '오류 로그',
    description: '실패 및 예외 발생'
  }];

  return <div className={twc("app-logs-page")}>
      <section className={twc("app-logs-panel")}>
        <div className={twc("app-logs-header")}>
          <div>
            <p className={twc("app-logs-eyebrow")}>Application Logs</p>
            <h2>앱 로그</h2>
            <span>
              대시보드 동작, 방화벽 요청, 오류 발생 내역을 확인합니다.
            </span>
          </div>

          <div className={twc("app-logs-header-actions")}>
            <div className={twc("ui-meta-chip app-logs-count-chip")}>
              총 {logs.length}개 · 마지막 기록 {lastLogTime}
            </div>

            <button type="button" className={twc("ui-control-btn ui-control-btn-danger")} onClick={handleClearLogs} disabled={logs.length === 0}>
              로그 비우기
            </button>
          </div>
        </div>

        {logs.length === 0 ? <div className={twc("app-logs-empty")}>
            <div className={twc("app-logs-empty-icon")}>L</div>
            <h3>로그가 없습니다.</h3>
            <p>앱에서 발생한 이벤트가 있으면 이곳에 표시됩니다.</p>
          </div> : <>
            <div className={twc("grid gap-3 pb-4 md:grid-cols-2 2xl:grid-cols-4")}> 
              {statCards.map(item => {
            const meta = LEVEL_META[item.key];
            return <article key={item.key} className={twc("rounded-[22px] border border-[var(--border)] bg-[var(--surface)] px-4 py-4 shadow-[var(--shadow-sm)] backdrop-blur-xl")}> 
                    <div className={twc("mb-3 flex items-start justify-between gap-3")}> 
                      <div>
                        <p className={twc("text-[11px] font-black uppercase tracking-[0.14em] text-[var(--text-soft)]")}>{item.key}</p>
                        <h3 className={twc(`mt-1 text-[15px] font-extrabold ${meta.accent}`)}>{item.title}</h3>
                      </div>
                      <span className={twc(`inline-flex min-w-[56px] justify-center rounded-full px-3 py-1 text-xs font-black ${meta.chip}`)}>{stats[item.key]}건</span>
                    </div>
                    <p className={twc("text-[12px] font-semibold leading-5 text-[var(--text-muted)]")}>{item.description}</p>
                  </article>;
          })}
            </div>

            <section className={twc("flex min-h-0 flex-1 flex-col overflow-hidden rounded-[24px] border border-[var(--border)] bg-[var(--surface-soft)]/70 p-3 shadow-[var(--shadow-sm)] backdrop-blur-xl")}> 
              <div className={twc("mb-3 flex flex-wrap items-center justify-between gap-3 px-1")}> 
                <div>
                  <p className={twc("text-[11px] font-black uppercase tracking-[0.14em] text-[var(--accent-dark)]")}>Live stream</p>
                  <h3 className={twc("mt-1 text-[18px] font-black tracking-[-0.03em] text-[var(--text-main)]")}>실시간 앱 이벤트 목록</h3>
                </div>
                <div className={twc("flex flex-wrap items-center gap-2 text-[12px] font-bold text-[var(--text-muted)]")}> 
                  <span className={twc("inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-[var(--card-bg)] px-3 py-1.5")}> 
                    <span className={twc("h-2 w-2 rounded-full bg-emerald-400")} />
                    현재 페이지 {pagedLogs.length}개
                  </span>
                  <span className={twc("inline-flex items-center rounded-full border border-[var(--border)] bg-[var(--card-bg)] px-3 py-1.5")}>페이지 {safePage} / {totalPages}</span>
                </div>
              </div>

              <div className={twc("min-h-0 flex-1 overflow-auto rounded-[20px] border border-[var(--border)] bg-[var(--card-bg)]/90")}> 
                <table className={twc("min-w-[760px] w-full border-collapse")}> 
                  <thead className={twc("sticky top-0 z-[1] bg-[var(--surface-strong)]/95 backdrop-blur-xl")}> 
                    <tr className={twc("border-b border-[var(--border-soft)]")}> 
                      <th className={twc("w-[72px] px-4 py-3 text-left text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-soft)]")}>#</th>
                      <th className={twc("w-[140px] px-4 py-3 text-left text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-soft)]")}>Level</th>
                      <th className={twc("px-4 py-3 text-left text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-soft)]")}>Message</th>
                      <th className={twc("w-[220px] px-4 py-3 text-left text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-soft)]")}>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedLogs.map((log, index) => {
                  const level = normalizeLevel(log.level);
                  const meta = LEVEL_META[level];
                  const absoluteIndex = (safePage - 1) * LOG_PAGE_SIZE + index + 1;
                  return <tr key={log.id || `${log.time}-${index}`} className={twc("border-b border-[var(--border-soft)]/80 transition-colors hover:bg-white/35 dark:hover:bg-white/5")}> 
                          <td className={twc("px-4 py-3 align-top text-[12px] font-bold text-[var(--text-soft)]")}>{absoluteIndex}</td>
                          <td className={twc("px-4 py-3 align-top")}> 
                            <div className={twc("flex items-center gap-2")}> 
                              <span className={twc(`h-2.5 w-2.5 rounded-full ${meta.dot}`)} />
                              <span className={twc(`inline-flex rounded-full px-3 py-1 text-[11px] font-black ${meta.chip}`)}>{meta.label}</span>
                            </div>
                          </td>
                          <td className={twc("px-4 py-3 align-top")}> 
                            <p className={twc("whitespace-pre-wrap break-words text-[13px] font-extrabold leading-6 text-[var(--text-main)]")}>{log.message}</p>
                          </td>
                          <td className={twc("px-4 py-3 align-top text-[12px] font-bold text-[var(--text-muted)]")}>{log.time || '-'}</td>
                        </tr>;
                })}
                  </tbody>
                </table>
              </div>
            </section>

            {totalPages > 1 ? <div className={twc("app-logs-footer")}> 
              <div className={twc("app-logs-page-info")}>페이지당 {LOG_PAGE_SIZE}개 표시 / {safePage} / {totalPages} 페이지</div>

              <div className={twc("app-logs-pagination")}> 
                <button type="button" onClick={() => setCurrentPage(1)} disabled={safePage === 1}>
                  처음
                </button>

                <button type="button" onClick={() => setCurrentPage(Math.max(1, safePage - 1))} disabled={safePage === 1}>
                  이전
                </button>

                {pageNumbers.map((page, index, arr) => {
              const prevPage = arr[index - 1];
              const showEllipsis = prevPage && page - prevPage > 1;
              return <span key={page} className={twc("app-logs-page-group")}> 
                      {showEllipsis ? <span className={twc("app-logs-ellipsis")}>...</span> : null}

                      <button type="button" className={twc(safePage === page ? 'active' : '')} onClick={() => setCurrentPage(page)} disabled={safePage === page}>
                        {page}
                      </button>
                    </span>;
            })}

                <button type="button" onClick={() => setCurrentPage(Math.min(totalPages, safePage + 1))} disabled={safePage === totalPages}>
                  다음
                </button>

                <button type="button" onClick={() => setCurrentPage(totalPages)} disabled={safePage === totalPages}>
                  마지막
                </button>
              </div>
            </div> : null}
          </>}
      </section>
    </div>;
}

export default LogsPage;
