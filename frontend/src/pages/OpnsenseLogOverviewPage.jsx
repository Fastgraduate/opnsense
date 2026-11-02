import { twc } from "../lib/twc";
import { useEffect, useMemo, useRef, useState } from 'react';
import { Chart, ArcElement, Tooltip, Legend } from 'chart.js';
import { OPN_LOG_EXPORT_COLUMNS, buildOpnsenseExportRows, downloadCsv, makeTimestampedFilename } from '../utils/logCsvExport';
Chart.register(ArcElement, Tooltip, Legend);
const DEFAULT_FILTERS = {
  historySize: 300,
  autoRefresh: false
};
const REFRESH_INTERVAL_MS = 30000;
const TOP_LIMIT = 10;
const CATEGORY_OPTIONS = [{
  key: 'action',
  label: '작업',
  tableLabel: '작업'
}, {
  key: 'interface',
  label: '인터페이스',
  tableLabel: '인터페이스'
}, {
  key: 'protocol',
  label: '프로토콜',
  tableLabel: '프로토콜'
}, {
  key: 'sourceIp',
  label: '출발지 IP',
  tableLabel: '출발지 IP'
}, {
  key: 'destinationIp',
  label: '목적지 IP',
  tableLabel: '목적지 IP'
}, {
  key: 'sourcePort',
  label: '출발지 포트',
  tableLabel: '출발지 포트'
}, {
  key: 'destinationPort',
  label: '목적지 포트',
  tableLabel: '목적지 포트'
}];
const CHART_COLORS = ['#3b82f6', '#93c5fd', '#f97316', '#fdba74', '#22c55e', '#86efac', '#ef4444', '#fca5a5', '#8b5cf6', '#c4b5fd', '#a16207'];
const toDisplayText = (value, fallback = '-') => {
  if (value == null || value === '') return fallback;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return String(value);
  }
  if (Array.isArray(value)) {
    const text = value.map(item => toDisplayText(item, '')).filter(Boolean).join(', ');
    return text || fallback;
  }
  if (typeof value === 'object') {
    if (value.name) return String(value.name);
    if (value.hostname) return String(value.hostname);
    if (value.ip) return toDisplayText(value.ip, fallback);
    if (value.address) return String(value.address);
    if (value.value) return toDisplayText(value.value, fallback);
    return JSON.stringify(value);
  }
  return fallback;
};
const splitAddress = value => {
  const text = toDisplayText(value, '');
  if (!text || text === '-') {
    return {
      ip: '-',
      port: '-'
    };
  }
  const match = text.match(/^(.*):(\d+)$/);
  if (!match) {
    return {
      ip: text,
      port: '-'
    };
  }
  return {
    ip: match[1],
    port: match[2]
  };
};
const normalizeAddress = (ip, port) => {
  const safeIp = toDisplayText(ip, '');
  const safePort = toDisplayText(port, '');
  if (!safeIp && !safePort) return '-';
  if (safeIp && safePort && safePort !== '-') return `${safeIp}:${safePort}`;
  return safeIp || safePort || '-';
};
const normalizeOneLog = (item, index) => {
  const src = item?._source || item?.raw || item || {};
  const interfaceName = item.interface || item.if || item.iface || src.interface || src.if || src.iface || '-';
  const direction = item.direction || item.dir || src.direction || src.dir || '-';
  const time = item.time || item.timestamp || item.datetime || item.__timestamp__ || src.time || src.timestamp || src.datetime || src.__timestamp__ || '-';
  const protocol = item.protocol || item.proto || item.protoname || src.protocol || src.proto || src.protoname || '-';
  const sourceIp = item.source_ip || item.src_ip || item.src || item.source || src.source_ip || src.src_ip || src.src || src.source || '-';
  const sourcePort = item.source_port || item.src_port || item.srcport || src.source_port || src.src_port || src.srcport || '';
  const destinationIp = item.destination_ip || item.dest_ip || item.dst_ip || item.destination || item.dest || item.dst || src.destination_ip || src.dest_ip || src.dst_ip || src.destination || src.dest || src.dst || '-';
  const destinationPort = item.destination_port || item.dest_port || item.dst_port || item.dstport || src.destination_port || src.dest_port || src.dst_port || src.dstport || '';
  const source = normalizeAddress(sourceIp, sourcePort);
  const destination = normalizeAddress(destinationIp, destinationPort);
  const parsedSource = splitAddress(source);
  const parsedDestination = splitAddress(destination);
  const action = item.action || item.act || src.action || src.act || '-';
  const label = item.label || item.rule || item.descr || item.description || src.label || src.rule || src.descr || src.description || '-';
  return {
    id: item.id || item.uuid || item.__digest__ || src.id || src.uuid || src.__digest__ || `${time}-${index}`,
    interface: toDisplayText(interfaceName).toLowerCase(),
    direction: toDisplayText(direction),
    time: toDisplayText(time),
    protocol: toDisplayText(protocol).toLowerCase(),
    source,
    destination,
    sourceIp: parsedSource.ip,
    sourcePort: parsedSource.port,
    destinationIp: parsedDestination.ip,
    destinationPort: parsedDestination.port,
    action: toDisplayText(action).toLowerCase(),
    label: toDisplayText(label),
    raw: src
  };
};
const normalizeLogs = payload => {
  let list = [];
  if (Array.isArray(payload?.rows)) list = payload.rows;else if (Array.isArray(payload?.data?.rows)) list = payload.data.rows;else if (Array.isArray(payload?.logs)) list = payload.logs;else if (Array.isArray(payload?.data)) list = payload.data;else if (Array.isArray(payload)) list = payload;
  return list.map((item, index) => normalizeOneLog(item, index));
};
const getLogValueByCategory = (log, categoryKey) => {
  if (categoryKey === 'action') return log.action;
  if (categoryKey === 'interface') {
    if (log.interface === 'em0') return 'wan';
    if (log.interface === 'em1') return 'lan';
    return log.interface;
  }
  if (categoryKey === 'protocol') return log.protocol;
  if (categoryKey === 'sourceIp') return log.sourceIp;
  if (categoryKey === 'destinationIp') return log.destinationIp;
  if (categoryKey === 'sourcePort') return log.sourcePort;
  if (categoryKey === 'destinationPort') return log.destinationPort;
  return '-';
};
const buildCategoryRows = (logs, categoryKey) => {
  const map = new Map();
  logs.forEach(log => {
    const rawValue = getLogValueByCategory(log, categoryKey);
    const key = toDisplayText(rawValue);
    if (!key || key === '-') return;
    map.set(key, (map.get(key) || 0) + 1);
  });
  const sorted = Array.from(map.entries()).map(([label, count]) => ({
    label,
    count
  })).sort((a, b) => b.count - a.count);
  if (sorted.length <= TOP_LIMIT) return sorted;
  const top = sorted.slice(0, TOP_LIMIT);
  const otherCount = sorted.slice(TOP_LIMIT).reduce((sum, item) => sum + item.count, 0);
  if (otherCount > 0) {
    top.push({
      label: '기타',
      count: otherCount
    });
  }
  return top;
};

function useIsDarkTheme() {
  const getValue = () => document.documentElement.classList.contains('dark');
  const [isDarkTheme, setIsDarkTheme] = useState(getValue);
  useEffect(() => {
    const root = document.documentElement;
    const observer = new MutationObserver(() => setIsDarkTheme(getValue()));
    observer.observe(root, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);
  return isDarkTheme;
}

function DonutChart({
  rows,
  total
}) {
  const canvasRef = useRef(null);
  const chartRef = useRef(null);
  const isDarkTheme = useIsDarkTheme();
  const labels = useMemo(() => rows.map(row => row.label), [rows]);
  const values = useMemo(() => rows.map(row => row.count), [rows]);
  const colors = useMemo(() => rows.map((_, index) => CHART_COLORS[index % CHART_COLORS.length]), [rows]);
  useEffect(() => {
    if (!canvasRef.current || chartRef.current) return;
    chartRef.current = new Chart(canvasRef.current, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: colors,
          borderColor: '#ffffff',
          borderWidth: 2,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '46%',
        animation: {
          duration: 650,
          easing: 'easeOutQuart'
        },
        plugins: {
          legend: {
            position: 'right',
            labels: {
              usePointStyle: true,
              boxWidth: 9,
              boxHeight: 9,
              color: isDarkTheme ? '#dbe7ff' : '#0f172a',
              font: {
                family: "'Pretendard Variable', 'Pretendard', 'Noto Sans KR', 'Apple SD Gothic Neo', system-ui, sans-serif",
                size: 13,
                weight: '800'
              }
            }
          },
          tooltip: {
            backgroundColor: isDarkTheme ? '#020817' : '#111827',
            titleColor: '#ffffff',
            bodyColor: isDarkTheme ? '#dbeafe' : '#e5e7eb',
            padding: 10,
            titleFont: {
              family: "'Pretendard Variable', 'Pretendard', 'Noto Sans KR', 'Apple SD Gothic Neo', system-ui, sans-serif",
              size: 13,
              weight: '900'
            },
            bodyFont: {
              family: "'Pretendard Variable', 'Pretendard', 'Noto Sans KR', 'Apple SD Gothic Neo', system-ui, sans-serif",
              size: 13,
              weight: '800'
            },
            callbacks: {
              label: context => {
                const value = Number(context.raw || 0);
                const percent = total > 0 ? Math.round(value / total * 100) : 0;
                return `${context.label}: ${value.toLocaleString()}건 (${percent}%)`;
              }
            }
          }
        }
      },
      plugins: [{
        id: 'percentageLabel',
        afterDatasetsDraw(chart) {
          const {
            ctx
          } = chart;
          const dataset = chart.data.datasets[0];
          const meta = chart.getDatasetMeta(0);
          ctx.save();
          ctx.fillStyle = isDarkTheme ? '#f8fbff' : '#0f172a';
          ctx.font = "800 13px 'Pretendard Variable', 'Pretendard', 'Noto Sans KR', 'Apple SD Gothic Neo', system-ui, sans-serif";
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          meta.data.forEach((arc, index) => {
            const value = Number(dataset.data[index] || 0);
            if (!value || !total) return;
            const percent = Math.round(value / total * 100);
            if (percent < 5) return;
            const position = arc.tooltipPosition();
            ctx.fillText(`${percent}%`, position.x, position.y);
          });
          ctx.restore();
        }
      }]
    });
    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, [isDarkTheme]);
  useEffect(() => {
    if (!chartRef.current) return;
    const chart = chartRef.current;
    chart.data.labels = labels;
    chart.data.datasets[0].data = values;
    chart.data.datasets[0].backgroundColor = colors;
    chart.options.plugins.legend.labels.color = isDarkTheme ? '#dbe7ff' : '#0f172a';
    chart.update();
  }, [labels, values, colors, isDarkTheme]);
  return <div className={twc("opn-overview-chart")}>
      <canvas ref={canvasRef} />
    </div>;
}
function OpnsenseLogOverviewPage({
  selectedFirewall,
  fetchOpnsenseLogs
}) {
  const [filters, setFilters] = useState(DEFAULT_FILTERS);
  const [activeCategory, setActiveCategory] = useState('action');
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState(null);
  const [error, setError] = useState('');
  const timerRef = useRef(null);
  const loadingRef = useRef(false);
  const activeMeta = CATEGORY_OPTIONS.find(item => item.key === activeCategory) || CATEGORY_OPTIONS[0];
  const loadLogs = async ({
    silent = false
  } = {}) => {
    if (loadingRef.current) return;
    if (!selectedFirewall) {
      setLogs([]);
      setError('방화벽을 먼저 선택하세요.');
      return;
    }
    try {
      loadingRef.current = true;
      if (!silent) setLoading(true);
      setError('');
      const limit = Math.min(Number(filters.historySize) || 300, 500);
      const data = await fetchOpnsenseLogs({
        search: '',
        field: 'any',
        operator: 'contains',
        tableSize: limit,
        historySize: limit,
        resolveHostnames: false,
        onlyImportant: false
      });
      setLogs(normalizeLogs(data));
      setLastUpdatedAt(new Date());
    } catch (err) {
      setError(err.message || 'OPNsense 로그 개요를 불러오지 못했습니다.');
    } finally {
      loadingRef.current = false;
      if (!silent) setLoading(false);
    }
  };
  useEffect(() => {
    loadLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall]);
  useEffect(() => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (!filters.autoRefresh || !selectedFirewall) return;
    timerRef.current = setInterval(() => {
      if (document.visibilityState === 'visible') {
        loadLogs({
          silent: true
        });
      }
    }, REFRESH_INTERVAL_MS);
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.autoRefresh, filters.historySize, selectedFirewall]);
  const categoryRows = useMemo(() => buildCategoryRows(logs, activeCategory), [logs, activeCategory]);
  const total = useMemo(() => categoryRows.reduce((sum, item) => sum + item.count, 0), [categoryRows]);
  const topItem = categoryRows[0] || null;
  const topRows = useMemo(() => categoryRows.slice(0, 4), [categoryRows]);
  const topShare = total > 0 && topItem ? Math.round(topItem.count / total * 100) : 0;
  const summaryItems = [{
    label: '수집 로그',
    value: `${logs.length.toLocaleString()}건`,
    tone: 'blue'
  }, {
    label: '집계 항목',
    value: `${categoryRows.length.toLocaleString()}개`,
    tone: 'violet'
  }, {
    label: '최다 비중',
    value: topItem ? `${topShare}%` : '-',
    tone: 'emerald'
  }, {
    label: '자동 갱신',
    value: filters.autoRefresh ? 'ON' : 'OFF',
    tone: filters.autoRefresh ? 'emerald' : 'slate'
  }];
  const handleChange = e => {
    const {
      name,
      value,
      type,
      checked
    } = e.target;
    setFilters(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : name === 'historySize' ? Number(value) : value
    }));
  };
  const handleExportCsv = () => {
    downloadCsv(makeTimestampedFilename('opnsense_log_overview'), OPN_LOG_EXPORT_COLUMNS, buildOpnsenseExportRows(logs));
  };
  return <div className={twc("opn-overview-page")}>
      <header className={twc("lw-header")}>
        <div>
          <p>LIVE · OPNsense</p>
          <h2>방화벽 로그 파일: 개요</h2>
        </div>

        <div className={twc("lw-tools")}>
          <span className={twc("ui-meta-chip")} role="status">{loading ? '개요 갱신 중' : '대기'}</span>
        </div>
      </header>

      <div className={twc("opn-overview-shell")}> 
        <aside className={twc("opn-overview-side")}> 
          <section className={twc("opn-overview-toolbar")}>
            <div className={twc("opn-overview-tabs")}>
              {CATEGORY_OPTIONS.map(item => <button key={item.key} type="button" className={twc(`ui-control-btn ${activeCategory === item.key ? 'ui-control-btn-active active' : ''}`)} onClick={() => setActiveCategory(item.key)}>
                  {item.label}
                </button>)}
            </div>

            <div className={twc("opn-overview-controls")}>
              <label>
                <input type="checkbox" name="autoRefresh" checked={filters.autoRefresh} onChange={handleChange} />
                자동 갱신
              </label>

              <select name="historySize" value={filters.historySize} onChange={handleChange}>
                <option value={100}>100개</option>
                <option value={300}>300개</option>
                <option value={500}>500개</option>
              </select>

              <button type="button" className={twc("ui-control-btn")} onClick={() => loadLogs()}>
                갱신
              </button>

              <button type="button" className={twc("ui-control-btn")} onClick={handleExportCsv} disabled={logs.length === 0}>
                CSV 내보내기
              </button>
            </div>
          </section>

          {error ? <div className={twc("opn-log-error")}>{error}</div> : null}

          <section className={twc("rounded-[24px] border border-[var(--border)] bg-[var(--surface)] p-4 font-[var(--font-body)] shadow-[var(--shadow-md)]")}> 
            <div className={twc("mb-4 flex items-center justify-between gap-3")}> 
              <div>
                <p className={twc("mb-1 text-[11px] font-black uppercase tracking-[0.14em] text-[var(--accent)]")}>Quick summary</p>
                <h3 className={twc("text-[18px] font-black tracking-[-0.03em] text-[var(--text-main)]")}>{activeMeta.label} 분포 요약</h3>
              </div>
              <span className={twc("rounded-full border border-[var(--border)] bg-white/70 px-3 py-1 text-[11px] font-black text-[var(--text-muted)] dark:bg-slate-950/40")}>{total.toLocaleString()}건 집계</span>
            </div>
            <div className={twc("grid gap-3 sm:grid-cols-2")}> 
              {summaryItems.map(item => <article key={item.label} className={twc("rounded-[18px] border border-[var(--border)] bg-white/70 px-4 py-3 dark:bg-slate-950/40")}>
                  <p className={twc("text-[11px] font-black uppercase tracking-[0.14em] text-[var(--text-muted)]")}>{item.label}</p>
                  <strong className={twc("mt-2 block text-[17px] font-black tracking-[-0.03em] text-[var(--text-main)]")}>{item.value}</strong>
                </article>)}
            </div>

            <div className={twc("mt-4")}> 
              <div className={twc("mb-3 flex items-center justify-between gap-3")}> 
                <p className={twc("text-[12px] font-black uppercase tracking-[0.12em] text-[var(--accent)]")}>Top 4 항목</p>
                {topItem ? <span className={twc("text-[11px] font-bold text-[var(--text-muted)]")}>최다: {topItem.label}</span> : null}
              </div>

              {topRows.length === 0 ? <div className={twc("rounded-[18px] border border-dashed border-[var(--border)] bg-white/50 px-4 py-6 text-center text-[12px] font-bold text-[var(--text-muted)] dark:bg-slate-950/20")}>
                  표시할 상위 항목이 없습니다.
                </div> : <div className={twc("grid gap-2.5")}>
                  {topRows.map((row, index) => {
                const ratio = total > 0 ? Math.max(8, Math.round(row.count / total * 100)) : 0;
                return <article key={row.label} className={twc("rounded-[16px] border border-[var(--border)] bg-white/70 px-3.5 py-3 dark:bg-slate-950/40")}> 
                        <div className={twc("mb-1.5 flex items-center justify-between gap-3")}> 
                          <strong className={twc("min-w-0 truncate text-[13px] font-extrabold text-[var(--text-main)]")}>#{index + 1} {row.label}</strong>
                          <span className={twc("shrink-0 text-[11px] font-black text-[var(--accent)]")}>{row.count.toLocaleString()}건</span>
                        </div>
                        <div className={twc("h-2 overflow-hidden rounded-full bg-slate-200/80 dark:bg-slate-800")}> 
                          <div className={twc("h-full rounded-full bg-gradient-to-r from-blue-500 via-cyan-400 to-violet-500")} style={{ width: `${ratio}%` }} />
                        </div>
                      </article>;
              })}
                </div>}
            </div>
          </section>
        </aside>

        <div className={twc("opn-overview-main")}> 
          <section className={twc("opn-overview-card")}>
            <div className={twc("opn-overview-card-header")}>
              <div>
                <p className={twc("opn-log-eyebrow")}>Category</p>
                <h3>{activeMeta.label} 기준 로그 분포</h3>
                <span>
                  전체 {logs.length.toLocaleString()}건 / 집계 {total.toLocaleString()}건
                  {lastUpdatedAt ? ` / 마지막 갱신: ${lastUpdatedAt.toLocaleTimeString()}` : ''}
                </span>
              </div>

              {topItem ? <div className={twc("opn-overview-top")}>
                  <span>최다 항목</span>
                  <strong>{topItem.label}</strong>
                  <em>{topItem.count.toLocaleString()}건</em>
                </div> : null}
            </div>

            {categoryRows.length === 0 ? <div className={twc("opn-overview-empty")}>
                표시할 로그 개요 데이터가 없습니다.
              </div> : <>
                <div className={twc("grid gap-4 px-[18px] pb-4 xl:grid-cols-[minmax(0,1.2fr)_minmax(280px,.8fr)]")}> 
                  <section className={twc("rounded-[22px] border border-[var(--border)] bg-white/70 p-3 font-[var(--font-body)] shadow-sm dark:bg-slate-950/35")}> 
                    <div className={twc("mb-2 px-2 pt-2")}> 
                      <p className={twc("text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-muted)]")}>Visual</p>
                      <h4 className={twc("mt-1 text-[16px] font-black tracking-[-0.03em] text-[var(--text-main)]")}>카테고리 분포 도넛 차트</h4>
                    </div>
                    <DonutChart rows={categoryRows} total={total} />
                  </section>

                  <section className={twc("rounded-[22px] border border-[var(--border)] bg-white/70 p-4 font-[var(--font-body)] shadow-sm dark:bg-slate-950/35")}> 
                    <div className={twc("mb-4 flex items-center justify-between gap-3")}> 
                      <div>
                        <p className={twc("text-[11px] font-black uppercase tracking-[0.12em] text-[var(--text-muted)]")}>Breakdown</p>
                        <h4 className={twc("mt-1 text-[16px] font-black tracking-[-0.03em] text-[var(--text-main)]")}>상위 분포 미리보기</h4>
                      </div>
                      <span className={twc("rounded-full bg-[var(--accent-soft)] px-3 py-1 text-[11px] font-black text-[var(--accent)]")}>{activeMeta.label}</span>
                    </div>

                    <div className={twc("grid gap-3")}> 
                      {topRows.map((row, index) => {
                    const percent = total > 0 ? Math.round(row.count / total * 100) : 0;
                    return <div key={`${row.label}-${index}`} className={twc("rounded-[18px] border border-[var(--border)] bg-white/80 px-4 py-3 dark:bg-slate-900/50")}> 
                            <div className={twc("mb-2 flex items-center justify-between gap-3")}> 
                              <strong className={twc("truncate text-[13px] font-black text-[var(--text-main)]")}>{row.label}</strong>
                              <span className={twc("shrink-0 text-[12px] font-black text-[var(--text-muted)]")}>{percent}%</span>
                            </div>
                            <div className={twc("h-2 overflow-hidden rounded-full bg-slate-200/80 dark:bg-slate-800")}> 
                              <div className={twc("h-full rounded-full bg-gradient-to-r from-indigo-500 via-sky-400 to-cyan-300")} style={{ width: `${Math.max(percent, 5)}%` }} />
                            </div>
                            <div className={twc("mt-2 text-[12px] font-bold text-[var(--text-muted)]")}>{row.count.toLocaleString()}건</div>
                          </div>;
                  })}
                    </div>
                  </section>
                </div>

                <div className={twc("opn-overview-table-wrap")}>
                  <table className={twc("opn-overview-table")}>
                    <thead>
                      <tr>
                        <th>{activeMeta.tableLabel}</th>
                        <th>#</th>
                      </tr>
                    </thead>

                    <tbody>
                      {categoryRows.map(row => <tr key={row.label}>
                          <td>{row.label}</td>
                          <td>{row.count.toLocaleString()}</td>
                        </tr>)}
                    </tbody>
                  </table>
                </div>
              </>}
          </section>
        </div>
      </div>
    </div>;
}
export default OpnsenseLogOverviewPage;
