function TrafficCard() {
  const samples = [15, 22, 18, 34, 48, 42, 55, 31, 25, 61, 44, 28]

  return (
    <div className="card traffic-card wide-card">
      <div className="card-title">트래픽 그래프</div>
      <div className="traffic-panel">
        <div>
          <div className="traffic-title">수신/송신 트래픽</div>
          <div className="traffic-chart">
            {samples.map((value, idx) => (
              <div className="traffic-bar-group" key={idx}>
                <div
                  className="traffic-bar rx"
                  style={{ height: `${value}%` }}
                  title={`수신 ${value}`}
                />
                <div
                  className="traffic-bar tx"
                  style={{ height: `${Math.max(8, value - 12)}%` }}
                  title={`송신 ${Math.max(8, value - 12)}`}
                />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

export default TrafficCard
