import { useEffect, useMemo, useRef } from 'react'
import {
  Chart,
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
} from 'chart.js'

Chart.register(
  ArcElement,
  BarController,
  BarElement,
  CategoryScale,
  DoughnutController,
  Filler,
  Legend,
  LinearScale,
  LineController,
  LineElement,
  PointElement,
  Tooltip,
)

const CHART_COLORS = {
  violet: '#8470ff',
  sky: '#67bfff',
  green: '#3ec972',
  yellow: '#f0bb33',
  red: '#ff5656',
  gray: '#94a3b8',
  lightGray: '#e5e7eb',
  dark: '#111827',
}

const toNumber = (value) => {
  if (value == null) return 0
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0

  const cleaned = String(value).replace(/[^\d.-]/g, '')
  const num = Number(cleaned)

  return Number.isFinite(num) ? num : 0
}

const formatNumber = (value) => toNumber(value).toLocaleString()

const formatBytes = (bytes) => {
  const value = toNumber(bytes)

  if (value <= 0) return '0 B/s'

  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s']
  let size = value
  let unitIndex = 0

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex += 1
  }

  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[unitIndex]}`
}

const pickDisplayValue = (value) => {
  if (value == null) return '-'

  if (['string', 'number', 'boolean'].includes(typeof value)) {
    return String(value)
  }

  if (Array.isArray(value)) {
    return value.map(pickDisplayValue).join(', ')
  }

  if (typeof value === 'object') {
    if (value.ipaddr !== undefined) return pickDisplayValue(value.ipaddr)
    if (value.address !== undefined) return pickDisplayValue(value.address)

    const firstPrimitive = Object.values(value).find((v) =>
      ['string', 'number', 'boolean'].includes(typeof v),
    )

    if (firstPrimitive !== undefined) return String(firstPrimitive)

    return JSON.stringify(value)
  }

  return String(value)
}

const parseSizeStringToBytes = (value) => {
  if (!value) return 0
  if (typeof value === 'number') return value

  const text = String(value).trim().toUpperCase()
  const match = text.match(/^([\d.]+)\s*([KMGTP]?)(I?B)?$/)

  if (!match) return 0

  const amount = Number(match[1])
  const unit = match[2]

  const map = {
    '': 1,
    K: 1024,
    M: 1024 ** 2,
    G: 1024 ** 3,
    T: 1024 ** 4,
    P: 1024 ** 5,
  }

  return amount * (map[unit] || 1)
}

const getTrafficLabel = (item, index) => {
  if (item?.time) return item.time

  if (item?.timestamp) {
    try {
      return new Date(item.timestamp).toLocaleTimeString('ko-KR', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch {
      return String(item.timestamp)
    }
  }

  return `${index + 1}`
}

const getTotalRx = (item) => {
  return Object.entries(item || {})
    .filter(([key]) => key.startsWith('rx_'))
    .reduce((sum, [, value]) => sum + toNumber(value), 0)
}

const getTotalTx = (item) => {
  return Object.entries(item || {})
    .filter(([key]) => key.startsWith('tx_'))
    .reduce((sum, [, value]) => sum + toNumber(value), 0)
}

function ChartCanvas({ type, data, options, height = 260 }) {
  const canvasRef = useRef(null)
  const chartRef = useRef(null)

  useEffect(() => {
    if (!canvasRef.current || chartRef.current) return

    chartRef.current = new Chart(canvasRef.current, {
      type,
      data,
      options,
    })

    return () => {
      if (chartRef.current) {
        chartRef.current.destroy()
        chartRef.current = null
      }
    }
  }, [type])

  useEffect(() => {
    if (!chartRef.current) return

    const chart = chartRef.current

    chart.data.labels = data.labels

    chart.data.datasets.forEach((dataset, index) => {
      const nextDataset = data.datasets[index]
      if (!nextDataset) return

      dataset.label = nextDataset.label
      dataset.data = nextDataset.data
      dataset.backgroundColor = nextDataset.backgroundColor
      dataset.borderColor = nextDataset.borderColor
      dataset.borderWidth = nextDataset.borderWidth
      dataset.borderRadius = nextDataset.borderRadius
      dataset.barPercentage = nextDataset.barPercentage
      dataset.categoryPercentage = nextDataset.categoryPercentage
      dataset.fill = nextDataset.fill
      dataset.tension = nextDataset.tension
      dataset.pointRadius = nextDataset.pointRadius
      dataset.pointHoverRadius = nextDataset.pointHoverRadius
      dataset.hoverOffset = nextDataset.hoverOffset
    })

    if (data.datasets.length > chart.data.datasets.length) {
      chart.data.datasets.push(
        ...data.datasets.slice(chart.data.datasets.length),
      )
    }

    if (data.datasets.length < chart.data.datasets.length) {
      chart.data.datasets.splice(data.datasets.length)
    }

    chart.options = {
      ...chart.options,
      ...options,
    }

    chart.update()
  }, [data, options])

  return (
    <div className="mosaic-chart-canvas" style={{ height }}>
      <canvas ref={canvasRef} />
    </div>
  )
}

function MetricCard({ title, value, subValue }) {
  return (
    <section className="mosaic-dashboard-card metric-card centered-metric-card">
      <div className="metric-card-header">
        <span>{title}</span>
      </div>

      <div className="metric-card-body">
        <strong>{value}</strong>
      </div>

      <p>{subValue}</p>
    </section>
  )
}

function DoughnutPanel({ title, centerValue, centerLabel, data }) {
  const chartData = useMemo(
    () => ({
      labels: data.map((item) => item.label),
      datasets: [
        {
          data: data.map((item) => item.value),
          backgroundColor: data.map((item) => item.color),
          borderWidth: 0,
          hoverOffset: 8,
        },
      ],
    }),
    [data],
  )

  const options = useMemo(
    () => ({
      cutout: '78%',
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 700,
        easing: 'easeOutQuart',
        animateRotate: false,
        animateScale: true,
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
              weight: 600,
            },
          },
        },
        tooltip: {
          backgroundColor: '#111827',
          titleColor: '#ffffff',
          bodyColor: '#e5e7eb',
          borderWidth: 0,
          padding: 10,
          callbacks: {
            label: (context) => {
              const label = context.label || '-'
              const value = context.raw ?? 0
              return `${label}: ${formatNumber(value)}`
            },
          },
        },
      },
    }),
    [],
  )

  return (
    <section className="mosaic-dashboard-card chart-panel">
      <div className="mosaic-card-header">
        <h3>{title}</h3>
      </div>

      <div className="doughnut-wrap">
        <ChartCanvas
          type="doughnut"
          data={chartData}
          options={options}
          height={260}
        />

        <div className="doughnut-center">
          <strong>{centerValue}</strong>
          <span>{centerLabel}</span>
        </div>
      </div>
    </section>
  )
}

function LinePanel({ title, value, subValue, labels, rxData, txData }) {
  const chartData = useMemo(
    () => ({
      labels,
      datasets: [
        {
          label: 'RX',
          data: rxData,
          borderColor: CHART_COLORS.violet,
          backgroundColor: 'rgba(132, 112, 255, 0.18)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
        },
        {
          label: 'TX',
          data: txData,
          borderColor: CHART_COLORS.sky,
          backgroundColor: 'rgba(103, 191, 255, 0.14)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 0,
          pointHoverRadius: 4,
        },
      ],
    }),
    [labels, rxData, txData],
  )

  const options = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 650,
        easing: 'easeOutCubic',
      },
      animations: {
        y: {
          duration: 650,
          easing: 'easeOutCubic',
        },
        x: {
          duration: 350,
          easing: 'easeOutCubic',
        },
        tension: {
          duration: 500,
          easing: 'linear',
        },
      },
      interaction: {
        intersect: false,
        mode: 'index',
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
              weight: 700,
            },
          },
        },
        tooltip: {
          backgroundColor: '#111827',
          titleColor: '#ffffff',
          bodyColor: '#e5e7eb',
          padding: 10,
          callbacks: {
            label: (context) => {
              return `${context.dataset.label}: ${formatBytes(context.raw)}`
            },
          },
        },
      },
      scales: {
        x: {
          grid: {
            display: false,
          },
          ticks: {
            color: '#94a3b8',
            maxRotation: 0,
            autoSkip: true,
          },
        },
        y: {
          beginAtZero: true,
          grid: {
            color: '#f1f5f9',
          },
          ticks: {
            color: '#94a3b8',
            callback: (value) => formatBytes(value),
          },
        },
      },
    }),
    [],
  )

  return (
    <section className="mosaic-dashboard-card traffic-panel">
      <div className="mosaic-card-header">
        <div>
          <h3>{title}</h3>

          <div className="traffic-main-value">
            <strong>{value}</strong>
            <span>{subValue}</span>
          </div>
        </div>
      </div>

      <ChartCanvas
        type="line"
        data={chartData}
        options={options}
        height={330}
      />
    </section>
  )
}

function BarPanel({ title, labels, datasets }) {
  const chartData = useMemo(
    () => ({
      labels,
      datasets,
    }),
    [labels, datasets],
  )

  const options = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      animation: {
        duration: 700,
        easing: 'easeOutQuart',
      },
      animations: {
        numbers: {
          type: 'number',
          properties: ['y', 'base'],
          duration: 700,
          easing: 'easeOutQuart',
        },
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
              weight: 700,
            },
          },
        },
        tooltip: {
          backgroundColor: '#111827',
          titleColor: '#ffffff',
          bodyColor: '#e5e7eb',
          padding: 10,
          callbacks: {
            label: (context) => {
              return `${context.dataset.label}: ${formatNumber(context.raw)}`
            },
          },
        },
      },
      scales: {
        x: {
          stacked: true,
          grid: {
            display: false,
          },
          ticks: {
            color: '#94a3b8',
          },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          grid: {
            color: '#f1f5f9',
          },
          ticks: {
            color: '#94a3b8',
          },
        },
      },
    }),
    [],
  )

  return (
    <section className="mosaic-dashboard-card chart-panel">
      <div className="mosaic-card-header">
        <h3>{title}</h3>
      </div>

      <ChartCanvas type="bar" data={chartData} options={options} height={280} />
    </section>
  )
}

function InfoTable({ title, columns, rows, emptyText }) {
  return (
    <section className="mosaic-dashboard-card table-panel">
      <div className="mosaic-card-header">
        <h3>{title}</h3>
      </div>

      <div className="mosaic-table-wrap">
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key}>{column.label}</th>
              ))}
            </tr>
          </thead>

          <tbody>
            {rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length}>{emptyText}</td>
              </tr>
            ) : (
              rows.map((row) => (
                <tr key={row.id}>
                  {columns.map((column) => (
                    <td key={column.key}>{row[column.key]}</td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function DashboardPage({
  product,
  status,
  system,
  systemSummary,
  interfaces,
  services,
  memory,
  memorySummary,
  disk,
  diskSummary,
  rules,
  aliases,
  autoRefresh,
  loading,
  trafficHistory,

  firewalls = [],
  selectedFirewall,
  selectedFirewallId,
  onSelectFirewall,
  onToggleAutoRefresh,
  onRefreshDashboard,
}) {
  const serviceRows = Array.isArray(services?.rows)
    ? services.rows
    : Array.isArray(services)
      ? services
      : []

  const interfaceRows = Array.isArray(interfaces)
    ? interfaces
    : Array.isArray(interfaces?.rows)
      ? interfaces.rows
      : []

  const ruleRows = Array.isArray(rules) ? rules : []
  const aliasRows = Array.isArray(aliases) ? aliases : []

  const activeServiceCount = serviceRows.filter((svc) =>
    ['1', 'true', 'running', 'up', 'active'].includes(
      String(svc?.running ?? svc?.status ?? svc?.state ?? '').toLowerCase(),
    ),
  ).length

  const firmwareVersion =
    product?.product_version ||
    product?.version ||
    status?.product?.product_version ||
    status?.product_version ||
    '-'

  const firmwareName =
    product?.product_name ||
    product?.name ||
    status?.product?.product_name ||
    'OPNsense'

  const mem = {
    total: memorySummary?.total || 0,
    used: memorySummary?.used || 0,
    free: memorySummary?.free || 0,
    used_percent: memorySummary?.used_percent || 0,
    source: memorySummary?.source || '-',
  }

  const diskInfo = {
    device: diskSummary?.device || '-',
    mountpoint: diskSummary?.mountpoint || '-',
    blocks: diskSummary?.blocks || '0 B',
    used: diskSummary?.used || '0 B',
    available: diskSummary?.available || '0 B',
    used_pct: diskSummary?.used_pct || 0,
    totalValue: parseSizeStringToBytes(diskSummary?.blocks),
    usedValue: parseSizeStringToBytes(diskSummary?.used),
  }

  const normalizedTrafficHistory = Array.isArray(trafficHistory)
    ? trafficHistory
    : []

  const latestTraffic =
    normalizedTrafficHistory.length > 0
      ? normalizedTrafficHistory[normalizedTrafficHistory.length - 1]
      : {}

  const interfaceNames = Object.keys(latestTraffic)
    .filter((key) => key.startsWith('rx_'))
    .map((key) => key.replace('rx_', ''))

  const interfaceSegments = interfaceNames
    .map((name) => {
      const rxBytes = toNumber(latestTraffic[`rx_${name}`])
      const txBytes = toNumber(latestTraffic[`tx_${name}`])

      return {
        label: name,
        value: rxBytes + txBytes,
        rxBytes,
        txBytes,
      }
    })
    .filter((item) => item.value > 0)
    .sort((a, b) => b.value - a.value)

  const memoryChart = [
    {
      label: '사용',
      value: mem.used,
      color: CHART_COLORS.violet,
    },
    {
      label: '여유',
      value: mem.free,
      color: CHART_COLORS.lightGray,
    },
  ]

  const diskUsed = diskInfo.usedValue || 0
  const diskTotal = diskInfo.totalValue || 0
  const diskFree = Math.max(diskTotal - diskUsed, 0)

  const diskChart = [
    {
      label: '사용',
      value: diskUsed,
      color: CHART_COLORS.green,
    },
    {
      label: '가용',
      value: diskFree,
      color: CHART_COLORS.lightGray,
    },
  ]

  const interfaceChart = interfaceSegments.slice(0, 5).map((item, index) => ({
    label: item.label,
    value: item.value,
    color: [
      CHART_COLORS.violet,
      CHART_COLORS.sky,
      CHART_COLORS.green,
      CHART_COLORS.yellow,
      CHART_COLORS.red,
    ][index],
  }))

  const normalizeRuleInterface = (rule) => {
    const raw =
      rule?.interface ||
      rule?.if ||
      rule?.interfaces ||
      rule?.descr ||
      rule?.description ||
      ''

    const text = String(raw).trim().toLowerCase()

    if (!text) return '기타'
    if (text.includes('lan')) return 'LAN'
    if (text.includes('wan')) return 'WAN'
    if (text.includes('opt1')) return 'OPT1'
    if (text.includes('loopback') || text.includes('lo0')) return 'LOOPBACK'

    return String(raw).toUpperCase()
  }

  const firewallCounts = {}

  ruleRows.forEach((rule) => {
    const label = normalizeRuleInterface(rule)
    firewallCounts[label] = (firewallCounts[label] || 0) + 1
  })

  const firewallLabels = Object.keys(firewallCounts)
  const firewallValues = Object.values(firewallCounts)

  const firewallBarDatasets = [
    {
      label: '규칙 수',
      data: firewallValues,
      backgroundColor: CHART_COLORS.violet,
      borderRadius: 6,
      barPercentage: 0.65,
      categoryPercentage: 0.65,
    },
  ]

  const interfaceBarLabels = interfaceSegments
    .slice(0, 6)
    .map((item) => item.label)

  const interfaceBarDatasets = [
    {
      label: 'RX',
      data: interfaceSegments.slice(0, 6).map((item) => item.rxBytes),
      backgroundColor: CHART_COLORS.sky,
      borderRadius: 6,
      barPercentage: 0.65,
      categoryPercentage: 0.65,
    },
    {
      label: 'TX',
      data: interfaceSegments.slice(0, 6).map((item) => item.txBytes),
      backgroundColor: CHART_COLORS.violet,
      borderRadius: 6,
      barPercentage: 0.65,
      categoryPercentage: 0.65,
    },
  ]

  const trafficLabels =
    normalizedTrafficHistory.length > 0
      ? normalizedTrafficHistory.map((item, index) =>
          getTrafficLabel(item, index),
        )
      : ['데이터 없음']

  const trafficRxData =
    normalizedTrafficHistory.length > 0
      ? normalizedTrafficHistory.map((item) => getTotalRx(item))
      : [0]

  const trafficTxData =
    normalizedTrafficHistory.length > 0
      ? normalizedTrafficHistory.map((item) => getTotalTx(item))
      : [0]

  const latestRx = trafficRxData[trafficRxData.length - 1] || 0
  const latestTx = trafficTxData[trafficTxData.length - 1] || 0

  const interfaceTableRows = interfaceRows.map((row, idx) => ({
    id: `${idx}-${pickDisplayValue(row?.identifier || row?.name || row?.if || `interface-${idx + 1}`)}`,
    name: pickDisplayValue(
      row?.identifier || row?.name || row?.if || `interface-${idx + 1}`,
    ),
    description: pickDisplayValue(
      row?.description || row?.descr || row?.friendly_name || '-',
    ),
    ip: pickDisplayValue(
      row?.ipaddr || row?.ip || row?.address || row?.ipv4 || '-',
    ),
    status: pickDisplayValue(
      row?.status || row?.link_state || row?.state || '-',
    ),
  }))

  return (
    <main className="mosaic-dashboard-page">
      <div className="mosaic-dashboard-container">
        <div className="mosaic-dashboard-header">
          <div className="mosaic-dashboard-title-area">
            <h1>Dashboard</h1>
            <p>
              OPNsense 방화벽 상태, 리소스 사용량, 인터페이스 트래픽을
              실시간으로 모니터링합니다.
            </p>
          </div>

          <div className="mosaic-dashboard-control-panel">
            <div className="mosaic-control-field firewall-select-field">
              <label>방화벽 선택</label>
              <select
                value={selectedFirewallId || selectedFirewall?.id || ''}
                onChange={(e) => {
                  if (onSelectFirewall) {
                    onSelectFirewall(e.target.value)
                  }
                }}
              >
                {firewalls.length === 0 ? (
                  <option value="">등록된 방화벽 없음</option>
                ) : (
                  firewalls.map((firewall) => (
                    <option key={firewall.id} value={firewall.id}>
                      {firewall.name ||
                        firewall.host ||
                        `Firewall ${firewall.id}`}
                    </option>
                  ))
                )}
              </select>
            </div>

            <div className="mosaic-control-field">
              <label>갱신 상태</label>
              <div
                className={`mosaic-status-chip ${loading ? 'loading' : 'ready'}`}
              >
                <span />
                {loading ? '데이터 갱신 중' : '실시간 수집 중'}
              </div>
            </div>

            <div className="mosaic-control-field">
              <label>자동 갱신</label>
              <button
                type="button"
                className={`mosaic-toggle-btn ${autoRefresh ? 'active' : ''}`}
                onClick={onToggleAutoRefresh}
              >
                {autoRefresh ? 'ON' : 'OFF'}
              </button>
            </div>

            <div className="mosaic-control-field">
              <label>수동 갱신</label>
              <button
                type="button"
                className="mosaic-refresh-btn"
                onClick={onRefreshDashboard}
                disabled={loading}
              >
                {loading ? '갱신 중' : '새로고침'}
              </button>
            </div>
          </div>
        </div>

        <div className="mosaic-grid">
          <section className="mosaic-dashboard-card overview-card col-span-6">
            <div>
              <span className="mosaic-label">Firewall Overview</span>
              <h2>{firmwareName}</h2>
              <p>
                {systemSummary?.hostname || '호스트 정보를 불러오는 중입니다.'}
              </p>
            </div>

            <div className="overview-version">
              <span>Firmware</span>
              <strong>{firmwareVersion}</strong>
            </div>
          </section>

          <div className="col-span-3">
            <MetricCard
              title="방화벽 규칙"
              value={formatNumber(ruleRows.length)}
              subValue="로드된 정책 수"
            />
          </div>

          <div className="col-span-3">
            <MetricCard
              title="실행 서비스"
              value={formatNumber(activeServiceCount)}
              subValue={`${formatNumber(serviceRows.length)}개 중 실행`}
            />
          </div>

          <div className="col-span-3">
            <MetricCard
              title="인터페이스"
              value={formatNumber(interfaceRows.length)}
              subValue="감지된 네트워크 인터페이스"
            />
          </div>

          <div className="col-span-3">
            <MetricCard
              title="Alias"
              value={formatNumber(aliasRows.length)}
              subValue="등록된 Alias"
            />
          </div>

          <div className="col-span-3">
            <MetricCard
              title="메모리 사용률"
              value={`${mem.used_percent || 0}%`}
              subValue={`${formatBytes(mem.used)} / ${formatBytes(mem.total)}`}
            />
          </div>

          <div className="col-span-3">
            <MetricCard
              title="디스크 사용률"
              value={`${diskInfo.used_pct || 0}%`}
              subValue={`${diskInfo.used} / ${diskInfo.blocks}`}
            />
          </div>

          <div className="col-span-6">
            <LinePanel
              title="실시간 트래픽"
              value={`RX ${formatBytes(latestRx)} / TX ${formatBytes(latestTx)}`}
              subValue="최근 수집 기준"
              labels={trafficLabels}
              rxData={trafficRxData}
              txData={trafficTxData}
            />
          </div>

          <div className="col-span-3">
            <DoughnutPanel
              title="메모리"
              centerValue={`${mem.used_percent || 0}%`}
              centerLabel="사용률"
              data={memoryChart}
            />
          </div>

          <div className="col-span-3">
            <DoughnutPanel
              title="디스크"
              centerValue={`${diskInfo.used_pct || 0}%`}
              centerLabel="사용률"
              data={diskChart}
            />
          </div>

          <div className="col-span-3">
            <DoughnutPanel
              title="인터페이스 트래픽"
              centerValue={`${interfaceChart.length}개`}
              centerLabel="인터페이스"
              data={
                interfaceChart.length > 0
                  ? interfaceChart
                  : [{ label: '없음', value: 1, color: CHART_COLORS.lightGray }]
              }
            />
          </div>

          <div className="col-span-3">
            <BarPanel
              title="방화벽 규칙 분포"
              labels={firewallLabels.length > 0 ? firewallLabels : ['없음']}
              datasets={
                firewallLabels.length > 0
                  ? firewallBarDatasets
                  : [
                      {
                        label: '규칙 수',
                        data: [0],
                        backgroundColor: CHART_COLORS.gray,
                        borderRadius: 6,
                      },
                    ]
              }
            />
          </div>

          <div className="col-span-6">
            <BarPanel
              title="인터페이스 RX / TX"
              labels={
                interfaceBarLabels.length > 0 ? interfaceBarLabels : ['없음']
              }
              datasets={
                interfaceBarLabels.length > 0
                  ? interfaceBarDatasets
                  : [
                      {
                        label: 'RX',
                        data: [0],
                        backgroundColor: CHART_COLORS.sky,
                        borderRadius: 6,
                      },
                      {
                        label: 'TX',
                        data: [0],
                        backgroundColor: CHART_COLORS.violet,
                        borderRadius: 6,
                      },
                    ]
              }
            />
          </div>

          <div className="col-span-6">
            <section className="mosaic-dashboard-card system-panel">
              <div className="mosaic-card-header">
                <h3>시스템 정보</h3>
              </div>

              <div className="system-info-list">
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
                  <strong>{systemSummary?.updates || '-'}</strong>
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

              {system?.error || status?.error ? (
                <div className="mosaic-error-text">
                  {system?.error || status?.error}
                </div>
              ) : null}
            </section>
          </div>

          <div className="col-span-6">
            <InfoTable
              title="인터페이스 정보"
              columns={[
                { key: 'name', label: '이름' },
                { key: 'description', label: '설명' },
                { key: 'ip', label: 'IP' },
                { key: 'status', label: '상태' },
              ]}
              rows={interfaceTableRows}
              emptyText="인터페이스 정보가 없습니다."
            />
          </div>

          <div className="col-span-6">
            <InfoTable
              title="상태 요약"
              columns={[
                { key: 'name', label: '항목' },
                { key: 'value', label: '값' },
              ]}
              rows={[
                {
                  id: 'rules',
                  name: '방화벽 규칙 수',
                  value: formatNumber(ruleRows.length),
                },
                {
                  id: 'services',
                  name: '실행 서비스 수',
                  value: `${formatNumber(activeServiceCount)} / ${formatNumber(serviceRows.length)}`,
                },
                {
                  id: 'interfaces',
                  name: '인터페이스 수',
                  value: formatNumber(interfaceRows.length),
                },
                {
                  id: 'aliases',
                  name: 'Alias 수',
                  value: formatNumber(aliasRows.length),
                },
                {
                  id: 'traffic',
                  name: '트래픽 데이터 포인트',
                  value: formatNumber(normalizedTrafficHistory.length),
                },
              ]}
              emptyText="상태 정보가 없습니다."
            />
          </div>
        </div>
      </div>
    </main>
  )
}

export default DashboardPage
