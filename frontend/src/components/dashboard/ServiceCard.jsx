import { twc } from "../../lib/twc";
function ServiceCard({
  autoRefresh
}) {
  return <div className={twc("card service-card")}>
      <div className={twc("card-title")}>서비스</div>
      <div className={twc("service-list")}>
        <div className={twc("service-row")}>
          <span>Packet Filter</span>
          <span className={twc("service-badge running")}>RUN</span>
        </div>
        <div className={twc("service-row")}>
          <span>Web GUI</span>
          <span className={twc("service-badge running")}>RUN</span>
        </div>
        <div className={twc("service-row")}>
          <span>Rules API</span>
          <span className={twc("service-badge running")}>RUN</span>
        </div>
        <div className={twc("service-row")}>
          <span>Auto Refresh</span>
          <span className={twc(`service-badge ${autoRefresh ? 'running' : 'stopped'}`)}>
            {autoRefresh ? 'ON' : 'OFF'}
          </span>
        </div>
      </div>
    </div>;
}
export default ServiceCard;
