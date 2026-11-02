import { twc } from "../../lib/twc";
function InfoTableCard({
  title,
  columns = [],
  rows = [],
  emptyText = '데이터가 없습니다.'
}) {
  return <div className={twc("card")}>
      <div className={twc("card-header-row")}><h3>{title}</h3></div>
      {rows.length === 0 ? <p>{emptyText}</p> : <div className={twc("table-wrap")}>
          <table className={twc("dashboard-table")}>
            <thead>
              <tr>
                {columns.map(col => <th key={col.key}>{col.label}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map(row => <tr key={row.id}>
                  {columns.map(col => <td key={col.key}>{row[col.key] ?? '-'}</td>)}
                </tr>)}
            </tbody>
          </table>
        </div>}
    </div>;
}
export default InfoTableCard;
