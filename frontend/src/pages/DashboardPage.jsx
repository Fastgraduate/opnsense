import DonutChartCard from '../components/dashboard/DonutChartCard'
import InfoTableCard from '../components/dashboard/InfoTableCard'
import MultiDonutChartCard from '../components/dashboard/MultiDonutChartCard'
import StatCard from '../components/dashboard/StatCard'
import SystemInfoCard from '../components/dashboard/SystemInfoCard'
import TrafficAreaChartCard from '../components/dashboard/TrafficAreaChartCard'

function DashboardPage({
  product,
  status,
  system,
  systemSummary,
  interfaces,
  services,
  traffic,
  memory,
  memorySummary,
  disk,
  diskSummary,
  rules,
  aliases,
  autoRefresh,
  loading,
  trafficHistory,
  currentInterfaceStats,
}) {
  const toNumber = (value) => {
    if (value === null || value === undefined) return 0
    if (typeof value === 'number') return Number.isFinite(value) ? value : 0

    const cleaned = String(value).replace(/[^\d.-]/g, '')
    const num = Number(cleaned)
    return Number.isFinite(num) ? num : 0
  }

  const formatNumber = (value) => toNumber(value).toLocaleString()

  const pickDisplayValue = (value) => {
    if (value === null || value === undefined) return '-'

    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean'
    ) {
      return String(value)
    }

    if (Array.isArray(value)) {
      return value.map((item) => pickDisplayValue(item)).join(', ')
    }

    if (typeof value === 'object') {
      if (value.ipaddr !== undefined) return pickDisplayValue(value.ipaddr)
      if (value.address !== undefined) return pickDisplayValue(value.address)
      if (value.value !== undefined) return pickDisplayValue(value.value)
      if (value.text !== undefined) return pickDisplayValue(value.text)

      const firstPrimitive = Object.values(value).find(
        (v) =>
          typeof v === 'string' ||
          typeof v === 'number' ||
          typeof v === 'boolean',
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

    const unitMap = {
      '': 1,
      K: 1024,
      M: 1024 ** 2,
      G: 1024 ** 3,
      T: 1024 ** 4,
      P: 1024 ** 5,
    }

    return amount * (unitMap[unit] || 1)
  }

  const normalizeServices = () => {
    if (!services) return []
    if (Array.isArray(services)) return services
    if (Array.isArray(services?.rows)) return services.rows
    if (Array.isArray(services?.data)) return services.data
    return []
  }

  const normalizeInterfaces = () => {
    if (!interfaces) return []
    if (Array.isArray(interfaces)) return interfaces
    if (Array.isArray(interfaces?.rows)) return interfaces.rows
    if (Array.isArray(interfaces?.data)) return interfaces.data

    if (typeof interfaces === 'object') {
      return Object.entries(interfaces).map(([name, value]) => ({
        name,
        ...(typeof value === 'object' ? value : { value }),
      }))
    }

    return []
  }

  const serviceRows = normalizeServices()
  const interfaceRows = normalizeInterfaces()

  const activeServiceCount = serviceRows.filter((svc) => {
    const running = String(
      svc?.running ?? svc?.status ?? svc?.state ?? '',
    ).toLowerCase()
    return ['1', 'true', 'running', 'up', 'active'].includes(running)
  }).length

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
    freeValue: parseSizeStringToBytes(diskSummary?.available),
  }

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

  const buildFirewallSegments = () => {
    if (!Array.isArray(rules) || rules.length === 0) return []

    const counts = {}

    rules.forEach((rule) => {
      const iface = normalizeRuleInterface(rule)
      const label = `${iface} 규칙`
      counts[label] = (counts[label] || 0) + 1
    })

    return Object.entries(counts)
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
  }

  const buildInterfaceSegments = () => {
    console.log('[DashboardPage] currentInterfaceStats:', currentInterfaceStats)

    if (
      !Array.isArray(currentInterfaceStats) ||
      currentInterfaceStats.length === 0
    ) {
      console.log('[DashboardPage] currentInterfaceStats 비어 있음')
      return []
    }

    const result = currentInterfaceStats
      .map((item) => {
        const trafficValue =
          item.totalBytes > 0 ? item.totalBytes : item.totalPackets || 0

        return {
          label: item.label,
          value: trafficValue,
          meta: {
            rxBytes: item.rxBytes,
            txBytes: item.txBytes,
            rxPackets: item.rxPackets,
            txPackets: item.txPackets,
            rxErrors: item.rxErrors,
            txErrors: item.txErrors,
            collisions: item.collisions,
            unit: item.totalBytes > 0 ? 'bytes' : 'packets',
          },
        }
      })
      .filter((item) => item.value > 0)
      .sort((a, b) => b.value - a.value)

    console.log('[DashboardPage] interfaceSegments:', result)
    return result
  }

  const interfaceSegments = buildInterfaceSegments()
  const firewallSegments = buildFirewallSegments()

  console.log('[DashboardPage] interfaceSegments 최종:', interfaceSegments)
  console.log('[DashboardPage] firewallSegments 최종:', firewallSegments)
  console.log('[DashboardPage] trafficHistory:', trafficHistory)

  return (
    <div className="page">
      <section className="dashboard-header card">
        <div>
          <h2>OPNsense Dashboard</h2>
          <p>자동 갱신: {autoRefresh ? '활성화' : '비활성화'}</p>
        </div>
        <div>
          <span className={`status-chip ${loading ? 'loading' : 'ready'}`}>
            {loading ? '데이터 갱신 중' : '실시간 상태'}
          </span>
        </div>
      </section>

      <section className="dashboard-grid four">
        <StatCard title="제품명" value={firmwareName} subValue="방화벽 장비" />
        <StatCard
          title="펌웨어 버전"
          value={firmwareVersion}
          subValue="현재 동작 버전"
        />
        <StatCard
          title="방화벽 규칙 수"
          value={formatNumber(rules.length)}
          subValue="로드된 규칙"
        />
        <StatCard
          title="실행 서비스 수"
          value={formatNumber(activeServiceCount)}
          subValue={`${formatNumber(serviceRows.length)}개 중 실행`}
        />
      </section>

      <section className="dashboard-grid three" style={{ marginTop: '16px' }}>
        <SystemInfoCard
          title="시스템 정보"
          items={[
            { label: '호스트명', value: systemSummary?.hostname || '-' },
            { label: '플랫폼', value: systemSummary?.platform || '-' },
            { label: 'CPU/아키텍처', value: systemSummary?.cpu_arch || '-' },
            { label: '업데이트 상태', value: systemSummary?.updates || '-' },
            {
              label: '인터페이스 수',
              value: formatNumber(interfaceRows.length),
            },
            { label: 'Alias 수', value: formatNumber(aliases.length) },
          ]}
          error={system?.error || status?.error}
        />

        <DonutChartCard
          title="메모리"
          percent={mem.used_percent}
          used={mem.used}
          total={mem.total}
          tooltipData={[
            { label: '전체', value: mem.total, type: 'bytes' },
            { label: '사용', value: mem.used, type: 'bytes' },
            { label: '여유', value: mem.free, type: 'bytes' },
            { label: '사용률', value: mem.used_percent, type: 'percent' },
          ]}
          error={memory?.error}
        />

        <DonutChartCard
          title="디스크"
          percent={diskInfo.used_pct}
          used={diskInfo.usedValue ?? 0}
          total={diskInfo.totalValue ?? 0}
          tooltipData={[
            { label: '전체', value: diskInfo.blocks, type: 'text' },
            { label: '사용', value: diskInfo.used, type: 'text' },
            { label: '가용', value: diskInfo.available, type: 'text' },
            { label: '사용률', value: diskInfo.used_pct, type: 'percent' },
          ]}
          error={disk?.error}
        />
      </section>

      <section className="dashboard-grid two" style={{ marginTop: '16px' }}>
        <MultiDonutChartCard
          title="인터페이스 통계"
          segments={interfaceSegments}
          emptyText="인터페이스 통계가 없습니다."
          type="interface"
          centerLabel={`${interfaceSegments.length}개`}
        />

        <MultiDonutChartCard
          title="방화벽"
          segments={firewallSegments}
          emptyText="방화벽 규칙 통계가 없습니다."
          type="firewall"
          centerLabel={`${firewallSegments.reduce((sum, item) => sum + item.value, 0)}개`}
        />
      </section>

      <section style={{ marginTop: '16px' }}>
        <TrafficAreaChartCard
          title="트래픽 그래프"
          history={trafficHistory}
          error={traffic?.error}
        />
      </section>

      <section className="dashboard-grid two" style={{ marginTop: '16px' }}>
        <InfoTableCard
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

        <InfoTableCard
          title="상태 요약"
          columns={[
            { key: 'name', label: '항목' },
            { key: 'value', label: '값' },
          ]}
          rows={[
            {
              id: 'host',
              name: '호스트명',
              value: systemSummary?.hostname || '-',
            },
            {
              id: 'platform',
              name: '플랫폼',
              value: systemSummary?.platform || '-',
            },
            {
              id: 'cpu',
              name: 'CPU/아키텍처',
              value: systemSummary?.cpu_arch || '-',
            },
            { id: 'memSource', name: '메모리 계산 기준', value: mem.source },
            {
              id: 'diskRoot',
              name: '루트 디스크',
              value: `${diskInfo.device} (${diskInfo.mountpoint})`,
            },
            {
              id: 'trafficPoints',
              name: '트래픽 데이터 포인트',
              value: formatNumber(trafficHistory?.length || 0),
            },
          ]}
          emptyText="상태 정보가 없습니다."
        />
      </section>
    </div>
  )
}

export default DashboardPage
