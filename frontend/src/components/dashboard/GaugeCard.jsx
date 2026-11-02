import { twc } from "../../lib/twc";
function GaugeCard({
  title,
  value,
  color = 'default'
}) {
  return <div className={twc("card gauge-card")}>
      <div className={twc("card-title")}>{title}</div>
      <div className={twc(`gauge-circle ${color === 'orange' ? 'orange' : ''}`)}>
        <div className={twc("gauge-value")}>{value}%</div>
      </div>
      <p className={twc("muted-text")}>대시보드 표시용</p>
    </div>;
}
export default GaugeCard;
