import { twc } from "../../lib/twc";
function SystemInfoCard({
  title,
  items = [],
  error = ''
}) {
  return <div className={twc("card")}>
      <div className={twc("card-header-row")}><h3>{title}</h3></div>
      {error ? <p className={twc("error-text")}>{String(error)}</p> : <div className={twc("summary-list")}>
          {items.map((item, idx) => <div className={twc("summary-row")} key={`${item.label}-${idx}`}>
              <span className={twc("summary-label")}>{item.label}</span>
              <span className={twc("summary-value")}>{item.value}</span>
            </div>)}
        </div>}
    </div>;
}
export default SystemInfoCard;
