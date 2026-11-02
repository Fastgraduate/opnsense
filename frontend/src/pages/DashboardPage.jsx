import { twc } from "../lib/twc";
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Chart, ArcElement, BarController, BarElement, CategoryScale, DoughnutController, Filler, Legend, LinearScale, LineController, LineElement, PointElement, Tooltip } from 'chart.js';
Chart.register(ArcElement, BarController, BarElement, CategoryScale, DoughnutController, Filler, Legend, LinearScale, LineController, LineElement, PointElement, Tooltip);
const CHART_COLORS = {
  violet: '#8470ff',
  sky: '#67bfff',
  green: '#3ec972',
  yellow: '#f0bb33',
  red: '#ff5656',
  gray: '#94a3b8',
  lightGray: '#e5e7eb',
  dark: '#111827'
};
const DASHBOARD_VIEWS = [{
  id: 'overview',
  label: '핵심 상태'
}, {
  id: 'traffic',
  label: '트래픽 분석'
}, {
  id: 'system',
  label: '시스템 상세'
}];
const toNumber = value => {
  if (value == null) return 0;
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;
  const cleaned = String(value).replace(/[^\d.-]/g, '');
  const num = Number(cleaned);
  return Number.isFinite(num) ? num : 0;
};
const formatNumber = value => toNumber(value).toLocaleString();
const formatBytes = bytes => {
  const value = toNumber(bytes);
  if (value <= 0) return '0 B/s';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
};
const formatStorageBytes = bytes => {
  const value = toNumber(bytes);
  if (value <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`;
};
const normalizeUpdateLabel = value => {
  const text = String(value ?? '').trim();
  if (!text || text === '-') return '-';
  if (/click\s+to\s+view/i.test(text)) return '확인 필요';
  return text;
};
const pickDisplayValue = value => {
  if (value == null) return '-';
  if (['string', 'number', 'boolean'].includes(typeof value)) {
    return String(value);
  }
  if (Array.isArray(value)) {
    return value.map(pickDisplayValue).join(', ');
  }
  if (typeof value === 'object') {
    if (value.ipaddr !== undefined) return pickDisplayValue(value.ipaddr);
    if (value.address !== undefined) return pickDisplayValue(value.address);
    const firstPrimitive = Object.values(value).find(v => ['string', 'number', 'boolean'].includes(typeof v));
    if (firstPrimitive !== undefined) return String(firstPrimitive);
    return JSON.stringify(value);
  }
  return String(value);
};
const parseSizeStringToBytes = value => {
  if (!value) return 0;
  if (typeof value === 'number') return value;
  const text = String(value).trim().toUpperCase();
  const match = text.match(/^([\d.]+)\s*([KMGTP]?)(I?B)?$/);
  if (!match) return 0;
  const amount = Number(match[1]);
  const unit = match[2];
  const map = {
    '': 1,
    K: 1024,
    M: 1024 ** 2,
    G: 1024 ** 3,
    T: 1024 ** 4,
    P: 1024 ** 5
  };
  return amount * (map[unit] || 1);
};
const getTrafficLabel = (item, index) => {
  if (item?.time) return item.time;
  if (item?.timestamp) {
    try {
      return new Date(item.timestamp).toLocaleTimeString('ko-KR', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return String(item.timestamp);
    }
  }
  return `${index + 1}`;
};
const getTotalRx = item => {
  return Object.entries(item || {}).filter(([key]) => key.startsWith('rx_')).reduce((sum, [, value]) => sum + toNumber(value), 0);
};
const getTotalTx = item => {
  return Object.entries(item || {}).filter(([key]) => key.startsWith('tx_')).reduce((sum, [, value]) => sum + toNumber(value), 0);
};
function ChartCanvas({
  type,
  data,
  options,
  height = 260
}) {
  const canvasRef = useRef(null);
  const chartRef = useRef(null);
  useEffect(() => {
    if (!canvasRef.current || chartRef.current) return;
    chartRef.current = new Chart(canvasRef.current, {
      type,
      data,
      options
    });
    return () => {
      if (chartRef.current) {
        chartRef.current.destroy();
        chartRef.current = null;
      }
    };
  }, [type]);
  useEffect(() => {
    if (!chartRef.current) return;
    const chart = chartRef.current;
    chart.data.labels = data.labels;
    chart.data.datasets.forEach((dataset, index) => {
      const nextDataset = data.datasets[index];
      if (!nextDataset) return;
      dataset.label = nextDataset.label;
      dataset.data = nextDataset.data;
      dataset.backgroundColor = nextDataset.backgroundColor;
      dataset.borderColor = nextDataset.borderColor;
      dataset.borderWidth = nextDataset.borderWidth;
      dataset.borderRadius = nextDataset.borderRadius;
      dataset.barPercentage = nextDataset.barPercentage;
      dataset.categoryPercentage = nextDataset.categoryPercentage;
      dataset.fill = nextDataset.fill;
      dataset.tension = nextDataset.tension;
      dataset.pointRadius = nextDataset.pointRadius;
      dataset.pointHoverRadius = nextDataset.pointHoverRadius;
      dataset.hoverOffset = nextDataset.hoverOffset;
    });
    if (data.datasets.length > chart.data.datasets.length) {
      chart.data.datasets.push(...data.datasets.slice(chart.data.datasets.length));
    }
    if (data.datasets.length < chart.data.datasets.length) {
      chart.data.datasets.splice(data.datasets.length);
    }
    chart.options = {
      ...chart.options,
      ...options
    };
    chart.update();
  }, [data, options]);
  return <div className={twc("mosaic-chart-canvas")} style={{
    height
  }}>
      <canvas ref={canvasRef} />
    </div>;
}
function MetricCard({
  title,
  value,
  subValue,
  tone = 'violet'
}) {
  return <article className={twc(`signal-tile signal-${tone}`)}>
      <span className={twc("signal-tile-light")} aria-hidden="true" />
      <p>{title}</p>
      <strong>{value}</strong>
      <small>{subValue}</small>
    </article>;
}
function ResourceGauge({
  label,
  value,
  detail,
  tone
}) {
  const safeValue = Math.max(0, Math.min(100, toNumber(value)));
  return <article className={twc("resource-gauge")}>
      <div className={twc(`resource-gauge-ring gauge-${tone}`)} style={{
      '--gauge-angle': `${safeValue * 3.6}deg`
    }}>
        <div>
          <strong>{safeValue}%</strong>
          <span>{label}</span>
        </div>
      </div>
      <p>{detail}</p>
    </article>;
}
function DoughnutPanel({
  title,
  centerValue,
  centerLabel,
  data,
  height = 260
}) {
  const chartData = useMemo(() => ({
    labels: data.map(item => item.label),
    datasets: [{
      data: data.map(item => item.value),
      backgroundColor: data.map(item => item.color),
      borderWidth: 0,
      hoverOffset: 8
    }]
  }), [data]);
  const options = useMemo(() => ({
    cutout: '78%',
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 700,
      easing: 'easeOutQuart',
      animateRotate: false,
      animateScale: true
    },
    plugins: {
      legend: {
        display: true,
        position: 'bottom',
        labels: {
          boxWidth: 10,
          boxHeight: 10,
          usePointStyle: true,
          color: '#64748b',
          font: {
            size: 12,
            weight: 600
          }
        }
      },
      tooltip: {
        backgroundColor: '#111827',
        titleColor: '#ffffff',
        bodyColor: '#e5e7eb',
        borderWidth: 0,
        padding: 10,
        callbacks: {
          label: context => {
            const label = context.label || '-';
            const value = context.raw ?? 0;
            return `${label}: ${formatNumber(value)}`;
          }
        }
      }
    }
  }), []);
  return <section className={twc("mosaic-dashboard-card chart-panel")}>
      <div className={twc("mosaic-card-header")}>
        <h3>{title}</h3>
      </div>

      <div className={twc("doughnut-wrap")}>
        <ChartCanvas type="doughnut" data={chartData} options={options} height={height} />

        <div className={twc("doughnut-center")}>
          <strong>{centerValue}</strong>
          <span>{centerLabel}</span>
        </div>
      </div>
    </section>;
}
function LinePanel({
  title,
  value,
  subValue,
  labels,
  rxData,
  txData,
  height = 330
}) {
  const chartData = useMemo(() => ({
    labels,
    datasets: [{
      label: 'RX',
      data: rxData,
      borderColor: CHART_COLORS.violet,
      backgroundColor: 'rgba(132, 112, 255, 0.18)',
      fill: true,
      tension: 0.35,
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4
    }, {
      label: 'TX',
      data: txData,
      borderColor: CHART_COLORS.sky,
      backgroundColor: 'rgba(103, 191, 255, 0.14)',
      fill: true,
      tension: 0.35,
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 4
    }]
  }), [labels, rxData, txData]);
  const options = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 650,
      easing: 'easeOutCubic'
    },
    animations: {
      y: {
        duration: 650,
        easing: 'easeOutCubic'
      },
      x: {
        duration: 350,
        easing: 'easeOutCubic'
      },
      tension: {
        duration: 500,
        easing: 'linear'
      }
    },
    interaction: {
      intersect: false,
      mode: 'index'
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
        align: 'end',
        labels: {
          color: '#64748b',
          usePointStyle: true,
          boxWidth: 8,
          font: {
            size: 12,
            weight: 700
          }
        }
      },
      tooltip: {
        backgroundColor: '#111827',
        titleColor: '#ffffff',
        bodyColor: '#e5e7eb',
        padding: 10,
        callbacks: {
          label: context => {
            return `${context.dataset.label}: ${formatBytes(context.raw)}`;
          }
        }
      }
    },
    scales: {
      x: {
        grid: {
          display: false
        },
        ticks: {
          color: '#94a3b8',
          maxRotation: 0,
          autoSkip: true
        }
      },
      y: {
        beginAtZero: true,
        grid: {
          color: '#f1f5f9'
        },
        ticks: {
          color: '#94a3b8',
          callback: value => formatBytes(value)
        }
      }
    }
  }), []);
  return <section className={twc("mosaic-dashboard-card traffic-panel")}>
      <div className={twc("mosaic-card-header")}>
        <div>
          <h3>{title}</h3>

          <div className={twc("traffic-main-value")}>
            <strong>{value}</strong>
            <span>{subValue}</span>
          </div>
        </div>
      </div>

      <ChartCanvas type="line" data={chartData} options={options} height={height} />
    </section>;
}
function BarPanel({
  title,
  labels,
  datasets,
  height = 280
}) {
  const chartData = useMemo(() => ({
    labels,
    datasets
  }), [labels, datasets]);
  const options = useMemo(() => ({
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 700,
      easing: 'easeOutQuart'
    },
    animations: {
      numbers: {
        type: 'number',
        properties: ['y', 'base'],
        duration: 700,
        easing: 'easeOutQuart'
      }
    },
    plugins: {
      legend: {
        display: true,
        position: 'top',
        align: 'end',
        labels: {
          color: '#64748b',
          usePointStyle: true,
          boxWidth: 8,
          font: {
            size: 12,
            weight: 700
          }
        }
      },
      tooltip: {
        backgroundColor: '#111827',
        titleColor: '#ffffff',
        bodyColor: '#e5e7eb',
        padding: 10,
        callbacks: {
          label: context => {
            return `${context.dataset.label}: ${formatNumber(context.raw)}`;
          }
        }
      }
    },
    scales: {
      x: {
        stacked: true,
        grid: {
          display: false
        },
        ticks: {
          color: '#94a3b8'
        }
      },
      y: {
        stacked: true,
        beginAtZero: true,
        grid: {
          color: '#f1f5f9'
        },
        ticks: {
          color: '#94a3b8'
        }
      }
    }
  }), []);
  return <section className={twc("mosaic-dashboard-card chart-panel")}>
      <div className={twc("mosaic-card-header")}>
        <h3>{title}</h3>
      </div>

      <ChartCanvas type="bar" data={chartData} options={options} height={height} />
    </section>;
}
function InfoTable({
  title,
  columns,
  rows,
  emptyText
}) {
  return <section className={twc("mosaic-dashboard-card table-panel")}>
      <div className={twc("mosaic-card-header")}>
        <h3>{title}</h3>
      </div>

      <div className={twc("mosaic-table-wrap")}>
        <table>
          <thead>
            <tr>
              {columns.map(column => <th key={column.key}>{column.label}</th>)}
            </tr>
          </thead>

          <tbody>
            {rows.length === 0 ? <tr>
                <td colSpan={columns.length}>{emptyText}</td>
              </tr> : rows.map(row => <tr key={row.id}>
                  {columns.map(column => <td key={column.key}>{row[column.key]}</td>)}
                </tr>)}
          </tbody>
        </table>
      </div>
    </section>;
}
function DashboardPage({
  product,
  status,
  system,
  systemSummary,
  interfaces,
  services,
  memorySummary,
  diskSummary,
  rules,
  aliases,
  autoRefresh,
  loading,
  trafficHistory,
  selectedFirewall,
  onToggleAutoRefresh,
  onRefreshDashboard
}) {
  const [activeView, setActiveView] = useState(0);
  const [deckDirection, setDeckDirection] = useState('next');
  const moveView = useCallback(step => {
    setDeckDirection(step > 0 ? 'next' : 'prev');
    setActiveView(current => (current + step + DASHBOARD_VIEWS.length) % DASHBOARD_VIEWS.length);
  }, []);
  const selectView = index => {
    if (index === activeView) return;
    setDeckDirection(index > activeView ? 'next' : 'prev');
    setActiveView(index);
  };
  useEffect(() => {
    const handleKeyDown = event => {
      const tagName = event.target?.tagName?.toLowerCase();
      if (['input', 'select', 'textarea'].includes(tagName)) return;
      if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
      if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
        event.preventDefault();
        event.stopPropagation();
        moveView(event.key === 'ArrowLeft' ? -1 : 1);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [moveView]);
  const serviceRows = Array.isArray(services?.rows) ? services.rows : Array.isArray(services) ? services : [];
  const interfaceRows = Array.isArray(interfaces) ? interfaces : Array.isArray(interfaces?.rows) ? interfaces.rows : [];
  const ruleRows = Array.isArray(rules) ? rules : [];
  const aliasRows = Array.isArray(aliases) ? aliases : [];
  const activeServiceCount = serviceRows.filter(svc => ['1', 'true', 'running', 'up', 'active'].includes(String(svc?.running ?? svc?.status ?? svc?.state ?? '').toLowerCase())).length;
  const firmwareVersion = product?.product_version || product?.version || status?.product?.product_version || status?.product_version || '-';
  const firmwareName = product?.product_name || product?.name || status?.product?.product_name || 'OPNsense';
  const mem = {
    total: memorySummary?.total || 0,
    used: memorySummary?.used || 0,
    free: memorySummary?.free || 0,
    used_percent: memorySummary?.used_percent || 0,
    source: memorySummary?.source || '-'
  };
  const diskInfo = {
    device: diskSummary?.device || '-',
    mountpoint: diskSummary?.mountpoint || '-',
    blocks: diskSummary?.blocks || '0 B',
    used: diskSummary?.used || '0 B',
    available: diskSummary?.available || '0 B',
    used_pct: diskSummary?.used_pct || 0,
    totalValue: parseSizeStringToBytes(diskSummary?.blocks),
    usedValue: parseSizeStringToBytes(diskSummary?.used)
  };
  const normalizedTrafficHistory = Array.isArray(trafficHistory) ? trafficHistory : [];
  const latestTraffic = normalizedTrafficHistory.length > 0 ? normalizedTrafficHistory[normalizedTrafficHistory.length - 1] : {};
  const interfaceNames = Object.keys(latestTraffic).filter(key => key.startsWith('rx_')).map(key => key.replace('rx_', ''));
  const interfaceSegments = interfaceNames.map(name => {
    const rxBytes = toNumber(latestTraffic[`rx_${name}`]);
    const txBytes = toNumber(latestTraffic[`tx_${name}`]);
    return {
      label: name,
      value: rxBytes + txBytes,
      rxBytes,
      txBytes
    };
  }).filter(item => item.value > 0).sort((a, b) => b.value - a.value);
  const interfaceChart = interfaceSegments.slice(0, 5).map((item, index) => ({
    label: item.label,
    value: item.value,
    color: [CHART_COLORS.violet, CHART_COLORS.sky, CHART_COLORS.green, CHART_COLORS.yellow, CHART_COLORS.red][index]
  }));
  const normalizeRuleInterface = rule => {
    const raw = rule?.interface || rule?.if || rule?.interfaces || rule?.descr || rule?.description || '';
    const text = String(raw).trim().toLowerCase();
    if (!text) return '기타';
    if (text.includes('lan')) return 'LAN';
    if (text.includes('wan')) return 'WAN';
    if (text.includes('opt1')) return 'OPT1';
    if (text.includes('loopback') || text.includes('lo0')) return 'LOOPBACK';
    return String(raw).toUpperCase();
  };
  const firewallCounts = {};
  ruleRows.forEach(rule => {
    const label = normalizeRuleInterface(rule);
    firewallCounts[label] = (firewallCounts[label] || 0) + 1;
  });
  const firewallLabels = Object.keys(firewallCounts);
  const firewallValues = Object.values(firewallCounts);
  const firewallBarDatasets = [{
    label: '규칙 수',
    data: firewallValues,
    backgroundColor: CHART_COLORS.violet,
    borderRadius: 6,
    barPercentage: 0.65,
    categoryPercentage: 0.65
  }];
  const interfaceBarLabels = interfaceSegments.slice(0, 6).map(item => item.label);
  const interfaceBarDatasets = [{
    label: 'RX',
    data: interfaceSegments.slice(0, 6).map(item => item.rxBytes),
    backgroundColor: CHART_COLORS.sky,
    borderRadius: 6,
    barPercentage: 0.65,
    categoryPercentage: 0.65
  }, {
    label: 'TX',
    data: interfaceSegments.slice(0, 6).map(item => item.txBytes),
    backgroundColor: CHART_COLORS.violet,
    borderRadius: 6,
    barPercentage: 0.65,
    categoryPercentage: 0.65
  }];
  const trafficLabels = normalizedTrafficHistory.length > 0 ? normalizedTrafficHistory.map((item, index) => getTrafficLabel(item, index)) : ['데이터 없음'];
  const trafficRxData = normalizedTrafficHistory.length > 0 ? normalizedTrafficHistory.map(item => getTotalRx(item)) : [0];
  const trafficTxData = normalizedTrafficHistory.length > 0 ? normalizedTrafficHistory.map(item => getTotalTx(item)) : [0];
  const latestRx = trafficRxData[trafficRxData.length - 1] || 0;
  const latestTx = trafficTxData[trafficTxData.length - 1] || 0;
  const updateLabel = normalizeUpdateLabel(systemSummary?.updates);
  const serviceStatusLabel = serviceRows.length > 0 ? `${activeServiceCount}/${serviceRows.length}` : '-';
  const interfaceTableRows = interfaceRows.map((row, idx) => ({
    id: `${idx}-${pickDisplayValue(row?.identifier || row?.name || row?.if || `interface-${idx + 1}`)}`,
    name: pickDisplayValue(row?.identifier || row?.name || row?.if || `interface-${idx + 1}`),
    description: pickDisplayValue(row?.description || row?.descr || row?.friendly_name || '-'),
    ip: pickDisplayValue(row?.ipaddr || row?.ip || row?.address || row?.ipv4 || '-'),
    status: pickDisplayValue(row?.status || row?.link_state || row?.state || '-')
  }));
  const handleGlassPointer = event => {
    const rect = event.currentTarget.getBoundingClientRect();
    const x = (event.clientX - rect.left) / rect.width * 100;
    const y = (event.clientY - rect.top) / rect.height * 100;
    event.currentTarget.style.setProperty('--glass-x', `${x}%`);
    event.currentTarget.style.setProperty('--glass-y', `${y}%`);
  };
  return <main className={twc("mosaic-dashboard-page command-dashboard")} onPointerMove={handleGlassPointer}>
      <div className={twc("command-canvas dashboard-deck")}>
        <header className={twc("deck-toolbar liquid-control-island")}>
          <span className={twc("liquid-lens")} aria-hidden="true" />
          <div className={twc("deck-current-view")} aria-live="polite">
            <small>Dashboard {activeView + 1} / {DASHBOARD_VIEWS.length}</small>
            <strong>{DASHBOARD_VIEWS[activeView].label}</strong>
          </div>

          <div className={twc("deck-dots")} role="tablist" aria-label="대시보드 화면 선택">
            {DASHBOARD_VIEWS.map((view, index) => <button key={view.id} type="button" role="tab" aria-selected={activeView === index} aria-label={`${index + 1}. ${view.label}`} className={twc(activeView === index ? 'active' : '')} onClick={() => selectView(index)} />)}
          </div>

          <div className={twc("deck-live-controls")}>
            <div className={twc(`liquid-live-state ${loading ? 'loading' : ''}`)}>
              <span />{loading ? '동기화 중' : 'Live'}
            </div>
            <button type="button" className={twc(`liquid-auto-button ${autoRefresh ? 'active' : ''}`)} onClick={onToggleAutoRefresh}>
              <span>Auto</span><strong>{autoRefresh ? 'ON' : 'OFF'}</strong>
            </button>
            <button type="button" className={twc("liquid-refresh-button")} onClick={onRefreshDashboard} disabled={loading} aria-label="대시보드 새로고침">
              <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.34 5.66M20 4v7h-7" /></svg>
            </button>
          </div>

          <div className={twc("deck-arrow-controls")}>
            <button type="button" onClick={() => moveView(-1)} aria-label="이전 대시보드 화면">‹</button>
            <button type="button" onClick={() => moveView(1)} aria-label="다음 대시보드 화면">›</button>
          </div>
        </header>

        <div className={twc("deck-viewport")}>
          <section key={`${activeView}-${deckDirection}`} className={twc(`deck-slide deck-slide-${deckDirection}`)} role="tabpanel" aria-label={DASHBOARD_VIEWS[activeView].label}>
            {activeView === 0 ? <div className={twc("deck-overview-grid")}>
                <section className={twc("command-hero deck-overview-hero")}>
                  <div className={twc("overview-identity")}>
                    <span>{selectedFirewall ? 'Protected firewall' : 'Firewall standby'}</span>
                    <strong>{systemSummary?.hostname || selectedFirewall?.name || 'OPNsense'}</strong>
                    <p>{firmwareName} · {firmwareVersion}</p>
                  </div>

                  <div className={twc(`security-orbit ${loading ? 'is-scanning' : ''}`)} aria-label="방화벽 연결 상태">
                    <span className={twc("orbit-ring orbit-ring-one")} aria-hidden="true" />
                    <span className={twc("orbit-ring orbit-ring-two")} aria-hidden="true" />
                    <span className={twc("orbit-ring orbit-ring-three")} aria-hidden="true" />
                    <span className={twc("orbit-glow")} aria-hidden="true" />
                    <div className={twc("security-core")}>
                      <span className={twc("security-core-dot")} />
                      <small>{selectedFirewall ? 'Protected' : 'Standby'}</small>
                      <strong>{systemSummary?.hostname || selectedFirewall?.name || 'OPNsense'}</strong>
                      <p>{loading ? '신호 동기화 중' : '실시간 연결'}</p>
                    </div>
                    <div className={twc("orbit-node orbit-node-rules")}><b>{formatNumber(ruleRows.length)}</b><span>Rules</span></div>
                    <div className={twc("orbit-node orbit-node-services")}><b>{formatNumber(activeServiceCount)}</b><span>Services</span></div>
                    <div className={twc("orbit-node orbit-node-interfaces")}><b>{formatNumber(interfaceRows.length)}</b><span>Links</span></div>
                  </div>

                  <div className={twc("overview-signal-column")}>
                    <div className={twc("traffic-now")}>
                      <span>현재 네트워크 I/O</span>
                      <strong>RX {formatBytes(latestRx)}</strong>
                      <strong>TX {formatBytes(latestTx)}</strong>
                    </div>
                    <div className={twc("signal-rail")}>
                      <MetricCard title="정책" value={formatNumber(ruleRows.length)} subValue="적용된 방화벽 룰" tone="violet" />
                      <MetricCard title="서비스" value={`${activeServiceCount}/${serviceRows.length}`} subValue="현재 실행 상태" tone="mint" />
                      <MetricCard title="인터페이스" value={formatNumber(interfaceRows.length)} subValue="감지된 네트워크" tone="sky" />
                      <MetricCard title="Alias" value={formatNumber(aliasRows.length)} subValue="등록된 객체" tone="pink" />
                    </div>
                  </div>

                  <aside className={twc("overview-resource-column")}>
                    <div className={twc("content-panel-heading")}><span>System pulse</span><h2>리소스</h2></div>
                    <div className={twc("resource-gauge-list")}>
                      <ResourceGauge label="Memory" value={mem.used_percent || 0} detail={`${formatStorageBytes(mem.used)} / ${formatStorageBytes(mem.total)}`} tone="violet" />
                      <ResourceGauge label="Disk" value={diskInfo.used_pct || 0} detail={`${diskInfo.used} / ${diskInfo.blocks}`} tone="mint" />
                    </div>
                    <div className={twc("resource-footnote")}><span>Root</span><strong>{diskInfo.device} · {diskInfo.mountpoint}</strong></div>
                  </aside>

                  <footer className={twc("overview-health-ribbon")}>
                    <div className={twc("health-ribbon-heading")}>
                      <span>Live telemetry</span>
                      <strong>현재 상태 요약</strong>
                      <p>운영에 필요한 핵심 상태만 요약합니다.</p>
                    </div>

                    <div className={twc("health-ribbon-stat")}>
                      <span>업데이트</span>
                      <strong>{updateLabel}</strong>
                      <small>펌웨어 상태</small>
                    </div>
                    <div className={twc("health-ribbon-stat")}>
                      <span>메모리 여유</span>
                      <strong>{formatStorageBytes(mem.free)}</strong>
                      <small>사용률 {Math.round(toNumber(mem.used_percent))}%</small>
                    </div>
                    <div className={twc("health-ribbon-stat")}>
                      <span>디스크 여유</span>
                      <strong>{diskInfo.available}</strong>
                      <small>사용률 {Math.round(toNumber(diskInfo.used_pct))}%</small>
                    </div>
                    <div className={twc("health-ribbon-stat")}>
                      <span>실행 서비스</span>
                      <strong>{serviceStatusLabel}</strong>
                      <small>활성 / 전체</small>
                    </div>
                  </footer>
                </section>
              </div> : null}

            {activeView === 1 ? <div className={twc("deck-analytics-grid command-analysis-grid")}>
                <div className={twc("command-traffic-panel")}>
            <LinePanel title="실시간 트래픽 파동" value={`RX ${formatBytes(latestRx)} / TX ${formatBytes(latestTx)}`} subValue="최근 수집 기준" labels={trafficLabels} rxData={trafficRxData} txData={trafficTxData} height={250} />
                </div>

                <div className={twc("command-flow-panel")}>
            <DoughnutPanel title="인터페이스 점유" centerValue={`${interfaceChart.length}개`} centerLabel="활성 링크" data={interfaceChart.length > 0 ? interfaceChart : [{
                label: '없음',
                value: 1,
                color: CHART_COLORS.lightGray
              }]} height={230} />
                </div>

                <div className={twc("command-rule-panel")}>
            <BarPanel title="정책 인터페이스 분포" labels={firewallLabels.length > 0 ? firewallLabels : ['없음']} datasets={firewallLabels.length > 0 ? firewallBarDatasets : [{
                label: '규칙 수',
                data: [0],
                backgroundColor: CHART_COLORS.gray,
                borderRadius: 6
              }]} height={210} />
                </div>

                <div className={twc("command-interface-panel")}>
            <BarPanel title="인터페이스 RX / TX" labels={interfaceBarLabels.length > 0 ? interfaceBarLabels : ['없음']} datasets={interfaceBarLabels.length > 0 ? interfaceBarDatasets : [{
                label: 'RX',
                data: [0],
                backgroundColor: CHART_COLORS.sky,
                borderRadius: 6
              }, {
                label: 'TX',
                data: [0],
                backgroundColor: CHART_COLORS.violet,
                borderRadius: 6
              }]} height={210} />
                </div>
              </div> : null}

            {activeView === 2 ? <div className={twc("deck-details-grid command-analysis-grid")}>
                <div className={twc("command-system-panel")}>
            <section className={twc("mosaic-dashboard-card system-panel")}>
              <div className={twc("mosaic-card-header")}>
                <h3>시스템 정보</h3>
              </div>

              <div className={twc("system-info-list")}>
                <div>
                  <span>호스트명</span>
                  <strong>{systemSummary?.hostname || '-'}</strong>
                </div>
                <div>
                  <span>플랫폼</span>
                  <strong>{systemSummary?.platform || '-'}</strong>
                </div>
                <div>
                  <span>CPU/아키텍처</span>
                  <strong>{systemSummary?.cpu_arch || '-'}</strong>
                </div>
                <div>
                  <span>업데이트 상태</span>
                  <strong>{updateLabel}</strong>
                </div>
                <div>
                  <span>메모리 기준</span>
                  <strong>{mem.source || '-'}</strong>
                </div>
                <div>
                  <span>루트 디스크</span>
                  <strong>
                    {diskInfo.device} ({diskInfo.mountpoint})
                  </strong>
                </div>
              </div>

              {system?.error || status?.error ? <div className={twc("mosaic-error-text")}>
                  {system?.error || status?.error}
                </div> : null}
            </section>
                </div>

                <div className={twc("command-table-panel command-interface-table")}>
            <InfoTable title="인터페이스 정보" columns={[{
                key: 'name',
                label: '이름'
              }, {
                key: 'description',
                label: '설명'
              }, {
                key: 'ip',
                label: 'IP'
              }, {
                key: 'status',
                label: '상태'
              }]} rows={interfaceTableRows} emptyText="인터페이스 정보가 없습니다." />
                </div>

                <div className={twc("command-table-panel command-summary-table")}>
            <InfoTable title="상태 요약" columns={[{
                key: 'name',
                label: '항목'
              }, {
                key: 'value',
                label: '값'
              }]} rows={[{
                id: 'rules',
                name: '방화벽 규칙 수',
                value: formatNumber(ruleRows.length)
              }, {
                id: 'services',
                name: '실행 서비스 수',
                value: `${formatNumber(activeServiceCount)} / ${formatNumber(serviceRows.length)}`
              }, {
                id: 'interfaces',
                name: '인터페이스 수',
                value: formatNumber(interfaceRows.length)
              }, {
                id: 'aliases',
                name: 'Alias 수',
                value: formatNumber(aliasRows.length)
              }, {
                id: 'traffic',
                name: '트래픽 데이터 포인트',
                value: formatNumber(normalizedTrafficHistory.length)
              }]} emptyText="상태 정보가 없습니다." />
                </div>
              </div> : null}
          </section>
        </div>
      </div>
    </main>;
}
export default DashboardPage;
