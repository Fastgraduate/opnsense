import { twc } from "../../lib/twc";
function StatCard({
  title,
  value,
  subValue = ''
}) {
  return <div className={twc("card stat-card")}>
      <div className={twc("stat-card__title")}>{title}</div>
      <div className={twc("stat-card__value")}>{value}</div>
      <div className={twc("stat-card__sub")}>{subValue}</div>
    </div>;
}
export default StatCard;
