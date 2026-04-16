function ServiceCard({ autoRefresh }) {
  return (
    <div className="card service-card">
      <div className="card-title">서비스</div>
      <div className="service-list">
        <div className="service-row">
          <span>Packet Filter</span>
          <span className="service-badge running">RUN</span>
        </div>
        <div className="service-row">
          <span>Web GUI</span>
          <span className="service-badge running">RUN</span>
        </div>
        <div className="service-row">
          <span>Rules API</span>
          <span className="service-badge running">RUN</span>
        </div>
        <div className="service-row">
          <span>Auto Refresh</span>
          <span
            className={`service-badge ${autoRefresh ? 'running' : 'stopped'}`}
          >
            {autoRefresh ? 'ON' : 'OFF'}
          </span>
        </div>
      </div>
    </div>
  )
}

export default ServiceCard
