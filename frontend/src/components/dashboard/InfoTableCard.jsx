function renderCellValue(value) {
  if (value === null || value === undefined) return '-'

  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) {
    return String(value)
  }

  if (Array.isArray(value)) {
    return value.map((item) => renderCellValue(item)).join(', ')
  }

  if (typeof value === 'object') {
    if (value.ipaddr !== undefined) return renderCellValue(value.ipaddr)
    if (value.address !== undefined) return renderCellValue(value.address)
    if (value.value !== undefined) return renderCellValue(value.value)
    if (value.text !== undefined) return renderCellValue(value.text)

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

function InfoTableCard({
  title,
  columns = [],
  rows = [],
  emptyText = '데이터가 없습니다.',
}) {
  return (
    <div className="card">
      <div className="card-header-row">
        <h3>{title}</h3>
      </div>

      {rows.length === 0 ? (
        <p>{emptyText}</p>
      ) : (
        <div className="table-wrap">
          <table className="dashboard-table">
            <thead>
              <tr>
                {columns.map((col) => (
                  <th key={col.key}>{col.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, idx) => (
                <tr key={row.id || idx}>
                  {columns.map((col) => (
                    <td key={`${row.id || idx}-${col.key}`}>
                      {renderCellValue(row[col.key])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default InfoTableCard
