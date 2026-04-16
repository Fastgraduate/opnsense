import { useMemo } from 'react'
import SystemInfoCard from '../components/dashboard/SystemInfoCard'
import GaugeCard from '../components/dashboard/GaugeCard'
import DonutChartCard from '../components/dashboard/DonutChartCard'
import ServiceCard from '../components/dashboard/ServiceCard'
import TrafficCard from '../components/dashboard/TrafficCard'

function DashboardPage({
  product,
  status,
  rules = [],
  system,
  interfaces,
  services,
  traffic,
  autoRefresh,
}) {
  const dashboardStats = useMemo(() => {
    const totalRules = rules.length
    const passRules = rules.filter((r) => r.action === 'pass').length
    const blockRules = rules.filter((r) => r.action === 'block').length

    const lanRules = rules.filter((r) => r.interface === 'lan').length
    const wanRules = rules.filter((r) => r.interface === 'wan').length
    const internalRules = rules.filter(
      (r) => r.interface !== 'lan' && r.interface !== 'wan',
    ).length

    const cpuPercent =
      Number(system?.cpu?.usage ?? system?.cpu_usage ?? system?.cpu ?? 0) ||
      Math.min(15 + totalRules * 4, 92)

    const memoryPercent =
      Number(
        system?.memory?.used_percent ??
          system?.memory_percent ??
          system?.memory?.used ??
          18,
      ) || 18

    const diskPercent =
      Number(
        system?.disk?.used_percent ??
          system?.disk_percent ??
          system?.storage?.used ??
          13,
      ) || 13

    return {
      totalRules,
      passRules,
      blockRules,
      lanRules,
      wanRules,
      internalRules,
      cpuPercent,
      memoryPercent,
      diskPercent,
    }
  }, [rules, system])

  const interfaceItems = useMemo(() => {
    if (!interfaces) {
      return [
        { label: 'WAN', value: dashboardStats.wanRules, color: '#2ecc71' },
        { label: 'LAN', value: dashboardStats.lanRules, color: '#f39c12' },
        {
          label: 'Internal',
          value: dashboardStats.internalRules,
          color: '#3498db',
        },
      ]
    }

    let wanCount = 0
    let lanCount = 0
    let internalCount = 0

    const values = Array.isArray(interfaces)
      ? interfaces
      : Object.values(interfaces)

    values.forEach((iface) => {
      const name = (iface?.identifier || iface?.name || iface?.if || '')
        .toString()
        .toLowerCase()

      if (name.includes('wan')) wanCount += 1
      else if (name.includes('lan')) lanCount += 1
      else internalCount += 1
    })

    return [
      {
        label: 'WAN',
        value: wanCount || dashboardStats.wanRules,
        color: '#2ecc71',
      },
      {
        label: 'LAN',
        value: lanCount || dashboardStats.lanRules,
        color: '#f39c12',
      },
      {
        label: 'Internal',
        value: internalCount || dashboardStats.internalRules,
        color: '#3498db',
      },
    ]
  }, [interfaces, dashboardStats])

  const serviceList = useMemo(() => {
    if (!services) return []

    if (Array.isArray(services)) return services
    if (Array.isArray(services.rows)) return services.rows
    if (Array.isArray(services.items)) return services.items

    return []
  }, [services])

  return (
    <>
      <div className="page-header">
        <h2>방화벽 상태 대시보드</h2>
        <p>OPNsense 상태와 자동 생성 규칙 현황을 한눈에 확인합니다.</p>
      </div>

      <div className="dashboard-layout">
        <SystemInfoCard product={product} status={status} system={system} />

        <GaugeCard title="메모리" value={dashboardStats.memoryPercent} />
        <GaugeCard
          title="디스크"
          value={dashboardStats.diskPercent}
          color="orange"
        />

        <DonutChartCard title="인터페이스 통계" items={interfaceItems} />

        <DonutChartCard
          title="방화벽"
          items={[
            {
              label: 'pass',
              value: dashboardStats.passRules,
              color: '#2980b9',
            },
            {
              label: 'block',
              value: dashboardStats.blockRules,
              color: '#ff7f0e',
            },
          ]}
        />

        <div className="card cpu-card">
          <div className="card-title">CPU</div>
          <div className="cpu-name">Firewall Load</div>
          <div className="cpu-graph">
            <div
              className="cpu-line"
              style={{ width: `${dashboardStats.cpuPercent}%` }}
            />
          </div>
          <strong>{dashboardStats.cpuPercent}%</strong>
        </div>

        <div className="card notice-card">
          <div className="card-title">상태 메시지</div>
          <p>{status?.status_msg || '상태 메시지가 없습니다.'}</p>
        </div>

        <ServiceCard autoRefresh={autoRefresh} services={serviceList} />
        <TrafficCard traffic={traffic} />

        <div className="card full-width dashboard-summary-card">
          <div className="card-title">요약</div>
          <div className="summary-grid">
            <div className="summary-item">
              <span>총 규칙 수</span>
              <strong>{dashboardStats.totalRules}</strong>
            </div>

            <div className="summary-item">
              <span>허용 규칙</span>
              <strong>{dashboardStats.passRules}</strong>
            </div>

            <div className="summary-item">
              <span>차단 규칙</span>
              <strong>{dashboardStats.blockRules}</strong>
            </div>

            <div className="summary-item">
              <span>자동 갱신</span>
              <strong>{autoRefresh ? 'ON' : 'OFF'}</strong>
            </div>

            <div className="summary-item">
              <span>WAN 관련</span>
              <strong>{dashboardStats.wanRules}</strong>
            </div>

            <div className="summary-item">
              <span>LAN 관련</span>
              <strong>{dashboardStats.lanRules}</strong>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}

export default DashboardPage
