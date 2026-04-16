function SystemInfoCard({ product, status, system }) {
  const hostname =
    system?.hostname || system?.name || system?.system?.hostname || '-'

  const uptime = system?.uptime || system?.system?.uptime || '-'

  const cpuInfo = system?.cpu?.model || system?.cpu?.type || system?.cpu || '-'

  const memoryInfo =
    system?.memory?.physmem || system?.memory?.total || system?.memory || '-'

  return (
    <div className="card system-info-card">
      <div className="card-title">시스템 정보</div>

      <div className="info-list">
        <div className="info-row">
          <span>이름</span>
          <strong>{product?.product_name || 'OPNsense'}</strong>
        </div>

        <div className="info-row">
          <span>버전</span>
          <strong>{product?.product_version || '-'}</strong>
        </div>

        <div className="info-row">
          <span>시리즈</span>
          <strong>{product?.product_series || '-'}</strong>
        </div>

        <div className="info-row">
          <span>아키텍처</span>
          <strong>{product?.product_arch || '-'}</strong>
        </div>

        <div className="info-row">
          <span>최신 버전</span>
          <strong>{product?.product_latest || '-'}</strong>
        </div>

        <div className="info-row">
          <span>상태</span>
          <strong>{status?.status || '-'}</strong>
        </div>

        <div className="info-row">
          <span>호스트명</span>
          <strong>{hostname}</strong>
        </div>

        <div className="info-row">
          <span>업타임</span>
          <strong>{uptime}</strong>
        </div>

        <div className="info-row">
          <span>CPU 정보</span>
          <strong>
            {typeof cpuInfo === 'object' ? JSON.stringify(cpuInfo) : cpuInfo}
          </strong>
        </div>

        <div className="info-row">
          <span>메모리 정보</span>
          <strong>
            {typeof memoryInfo === 'object'
              ? JSON.stringify(memoryInfo)
              : memoryInfo}
          </strong>
        </div>
      </div>
    </div>
  )
}

export default SystemInfoCard
