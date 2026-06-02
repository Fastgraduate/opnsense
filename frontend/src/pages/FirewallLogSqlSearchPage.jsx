import { useEffect, useMemo, useRef, useState } from 'react'
import '../styles/logCsvExport.css'
import {
  KIBANA_EXPORT_COLUMNS,
  buildElasticExportRows,
  downloadCsv,
  makeTimestampedFilename,
} from '../utils/logCsvExport'

const DEFAULT_SQL = `SELECT *
FROM logs
WHERE event_type = 'alert'
ORDER BY timestamp DESC
LIMIT 100`

const SQL_SAMPLES = [
  {
    title: '최근 전체 로그',
    sql: `SELECT *
FROM logs
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: 'Alert 로그',
    sql: `SELECT *
FROM logs
WHERE event_type = 'alert'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: 'Flow 로그',
    sql: `SELECT *
FROM logs
WHERE event_type = 'flow'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: '특정 출발지 IP',
    sql: `SELECT *
FROM logs
WHERE source_ip LIKE '192.168'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: '특정 목적지 IP',
    sql: `SELECT *
FROM logs
WHERE destination_ip LIKE '8.8.8.8'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: 'TCP 로그',
    sql: `SELECT *
FROM logs
WHERE protocol = 'TCP'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: 'UDP 로그',
    sql: `SELECT *
FROM logs
WHERE protocol = 'UDP'
ORDER BY timestamp DESC
LIMIT 100`,
  },
  {
    title: 'DNS 로그',
    sql: `SELECT *
FROM logs
WHERE message LIKE 'dns'
ORDER BY timestamp DESC
LIMIT 100`,
  },
]

const FIELD_ALIASES = {
  timestamp: ['timestamp', '@timestamp', 'time'],
  time: ['timestamp', '@timestamp', 'time'],

  event_type: ['event_type', 'action', 'event.type', 'messageJson.event_type'],
  action: ['action', 'event_type', 'event.action', 'messageJson.event_type'],

  interface: ['interface', 'in_iface', 'messageJson.in_iface'],
  in_iface: ['interface', 'in_iface', 'messageJson.in_iface'],

  protocol: ['protocol', 'proto', 'messageJson.proto', 'network.transport'],
  proto: ['protocol', 'proto', 'messageJson.proto', 'network.transport'],

  source_ip: ['source_ip', 'src_ip', 'source.ip', 'messageJson.src_ip'],
  src_ip: ['source_ip', 'src_ip', 'source.ip', 'messageJson.src_ip'],

  source_port: [
    'source_port',
    'src_port',
    'source.port',
    'messageJson.src_port',
  ],
  src_port: ['source_port', 'src_port', 'source.port', 'messageJson.src_port'],

  destination_ip: [
    'destination_ip',
    'dest_ip',
    'dst_ip',
    'destination.ip',
    'messageJson.dest_ip',
  ],
  dest_ip: [
    'destination_ip',
    'dest_ip',
    'dst_ip',
    'destination.ip',
    'messageJson.dest_ip',
  ],
  dst_ip: [
    'destination_ip',
    'dest_ip',
    'dst_ip',
    'destination.ip',
    'messageJson.dest_ip',
  ],

  destination_port: [
    'destination_port',
    'dest_port',
    'dst_port',
    'destination.port',
    'messageJson.dest_port',
  ],
  dest_port: [
    'destination_port',
    'dest_port',
    'dst_port',
    'destination.port',
    'messageJson.dest_port',
  ],
  dst_port: [
    'destination_port',
    'dest_port',
    'dst_port',
    'destination.port',
    'messageJson.dest_port',
  ],

  rule: ['rule', 'messageJson.alert.signature', 'suricata.eve.alert.signature'],
  signature: [
    'rule',
    'messageJson.alert.signature',
    'suricata.eve.alert.signature',
  ],

  severity: ['severity', 'messageJson.alert.severity', 'event.severity'],
  category: ['category', 'messageJson.alert.category', 'event.category'],
  host: ['host', 'host.name'],
  message: ['raw.message', 'message', 'exportRow.message'],
}

const SELECTABLE_COLUMNS = [
  'timestamp',
  'event_type',
  'interface',
  'protocol',
  'source_ip',
  'source_port',
  'destination_ip',
  'destination_port',
  'rule',
  'severity',
  'category',
  'host',
]

const toText = (value, fallback = '-') => {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

const normalizeSql = (sql) => {
  return String(sql || '')
    .replace(/\r/g, '')
    .replace(/--.*$/gm, '')
    .replace(/\s+/g, ' ')
    .trim()
}

const getNested = (obj, path) => {
  if (!obj || !path) return undefined

  return path.split('.').reduce((current, key) => {
    if (current === null || current === undefined) return undefined
    if (typeof current !== 'object') return undefined
    return current[key]
  }, obj)
}

const getRowValue = (row, field) => {
  const normalizedField = String(field || '')
    .trim()
    .toLowerCase()
  const candidates = FIELD_ALIASES[normalizedField] || [normalizedField]

  for (const candidate of candidates) {
    const direct = row?.[candidate]
    if (direct !== undefined && direct !== null && direct !== '') return direct

    const fromMessage = getNested(row?.messageJson, candidate)
    if (
      fromMessage !== undefined &&
      fromMessage !== null &&
      fromMessage !== ''
    ) {
      return fromMessage
    }

    const fromRaw = getNested(row?.raw, candidate)
    if (fromRaw !== undefined && fromRaw !== null && fromRaw !== '') {
      return fromRaw
    }

    const fromExport = getNested(row?.exportRow, candidate)
    if (fromExport !== undefined && fromExport !== null && fromExport !== '') {
      return fromExport
    }
  }

  return ''
}

const parseSelectColumns = (sql) => {
  const match = sql.match(/select\s+(.+?)\s+from\s+/i)

  if (!match) return SELECTABLE_COLUMNS

  const raw = match[1].trim()

  if (raw === '*') return SELECTABLE_COLUMNS

  return raw
    .split(',')
    .map((column) => column.trim())
    .filter(Boolean)
}

const parseLimit = (sql) => {
  const match = sql.match(/\blimit\s+(\d+)/i)
  if (!match) return 100

  const parsed = Number(match[1])
  if (!Number.isFinite(parsed)) return 100

  return Math.max(1, Math.min(parsed, 500))
}

const parseOrder = (sql) => {
  const match = sql.match(/\border\s+by\s+([a-zA-Z0-9_@.]+)(?:\s+(asc|desc))?/i)

  if (!match) {
    return {
      field: 'timestamp',
      direction: 'desc',
    }
  }

  return {
    field: match[1],
    direction: String(match[2] || 'asc').toLowerCase(),
  }
}

const extractWhereText = (sql) => {
  const match = sql.match(/\bwhere\s+(.+?)(?:\border\s+by\b|\blimit\b|$)/i)
  return match ? match[1].trim() : ''
}

const parseConditions = (whereText) => {
  if (!whereText) return []

  return whereText
    .split(/\s+and\s+/i)
    .map((condition) => condition.trim())
    .filter(Boolean)
    .map((condition) => {
      const likeMatch = condition.match(
        /^([a-zA-Z0-9_@.]+)\s+like\s+['"]?(.+?)['"]?$/i,
      )

      if (likeMatch) {
        return {
          field: likeMatch[1],
          operator: 'like',
          value: likeMatch[2],
        }
      }

      const compareMatch = condition.match(
        /^([a-zA-Z0-9_@.]+)\s*(=|!=|>=|<=|>|<)\s*['"]?(.+?)['"]?$/i,
      )

      if (compareMatch) {
        return {
          field: compareMatch[1],
          operator: compareMatch[2],
          value: compareMatch[3],
        }
      }

      return null
    })
    .filter(Boolean)
}

const compareValues = (leftValue, operator, rightValue) => {
  const leftText = toText(leftValue, '').toLowerCase()
  const rightText = toText(rightValue, '').toLowerCase()

  if (operator === 'like') {
    return leftText.includes(rightText)
  }

  if (operator === '=') {
    return leftText === rightText
  }

  if (operator === '!=') {
    return leftText !== rightText
  }

  const leftNumber = Number(leftValue)
  const rightNumber = Number(rightValue)

  if (!Number.isNaN(leftNumber) && !Number.isNaN(rightNumber)) {
    if (operator === '>') return leftNumber > rightNumber
    if (operator === '<') return leftNumber < rightNumber
    if (operator === '>=') return leftNumber >= rightNumber
    if (operator === '<=') return leftNumber <= rightNumber
  }

  if (operator === '>') return leftText > rightText
  if (operator === '<') return leftText < rightText
  if (operator === '>=') return leftText >= rightText
  if (operator === '<=') return leftText <= rightText

  return true
}

const inferServerParams = (conditions, limit) => {
  const params = {
    minutes: 1440,
    size: limit,
    action: '',
    interface: '',
    query: '',
  }

  const queryParts = []

  for (const condition of conditions) {
    const field = String(condition.field || '').toLowerCase()
    const value = String(condition.value || '').replace(/%/g, '')

    if (
      ['event_type', 'action'].includes(field) &&
      condition.operator === '='
    ) {
      params.action = value
      continue
    }

    if (
      ['interface', 'in_iface'].includes(field) &&
      condition.operator === '='
    ) {
      params.interface = value
      continue
    }

    if (
      [
        'message',
        'source_ip',
        'src_ip',
        'destination_ip',
        'dest_ip',
        'dst_ip',
        'protocol',
        'proto',
        'rule',
        'signature',
      ].includes(field)
    ) {
      queryParts.push(value)
    }
  }

  params.query = queryParts.join(' ').trim()

  return params
}

const runClientSql = (rows, parsedSql) => {
  const { conditions, order, limit } = parsedSql

  let result = [...rows]

  if (conditions.length > 0) {
    result = result.filter((row) => {
      return conditions.every((condition) => {
        const rowValue = getRowValue(row, condition.field)
        return compareValues(rowValue, condition.operator, condition.value)
      })
    })
  }

  if (order?.field) {
    result.sort((a, b) => {
      const aValue = getRowValue(a, order.field)
      const bValue = getRowValue(b, order.field)

      const aNumber = Number(aValue)
      const bNumber = Number(bValue)

      let compareResult = 0

      if (!Number.isNaN(aNumber) && !Number.isNaN(bNumber)) {
        compareResult = aNumber - bNumber
      } else {
        compareResult = toText(aValue, '').localeCompare(toText(bValue, ''))
      }

      return order.direction === 'desc' ? -compareResult : compareResult
    })
  }

  return result.slice(0, limit)
}

const parseSql = (sql) => {
  const normalized = normalizeSql(sql)

  if (!/^select\s+/i.test(normalized)) {
    throw new Error('SELECT 문으로 시작해야 합니다.')
  }

  if (!/\sfrom\s+/i.test(normalized)) {
    throw new Error('FROM logs 구문이 필요합니다.')
  }

  const fromMatch = normalized.match(/\sfrom\s+([a-zA-Z0-9_]+)/i)

  if (!fromMatch || fromMatch[1].toLowerCase() !== 'logs') {
    throw new Error('FROM logs 형식만 지원합니다.')
  }

  const whereText = extractWhereText(normalized)
  const conditions = parseConditions(whereText)
  const columns = parseSelectColumns(normalized)
  const limit = parseLimit(normalized)
  const order = parseOrder(normalized)

  return {
    normalized,
    whereText,
    conditions,
    columns,
    limit,
    order,
  }
}

function SqlResultModal({ log, onClose }) {
  if (!log) return null

  return (
    <div className="event-log-modal-backdrop" onClick={onClose}>
      <div className="event-log-modal" onClick={(e) => e.stopPropagation()}>
        <div className="event-log-modal-header">
          <div>
            <p className="event-log-eyebrow">SQL Result Detail</p>
            <h3>SQL 검색 결과 상세</h3>
          </div>

          <button type="button" onClick={onClose}>
            닫기
          </button>
        </div>

        <div className="event-log-modal-summary">
          <span>시간: {toText(log.timestamp)}</span>
          <span>이벤트: {toText(getRowValue(log, 'event_type'))}</span>
          <span>프로토콜: {toText(getRowValue(log, 'protocol'))}</span>
          <span>출발지: {toText(getRowValue(log, 'source_ip'))}</span>
          <span>목적지: {toText(getRowValue(log, 'destination_ip'))}</span>
        </div>

        <pre className="event-log-modal-pre">
          {JSON.stringify(log.raw || log, null, 2)}
        </pre>
      </div>
    </div>
  )
}

function FirewallLogSqlSearchPage({ selectedFirewall, fetchEventLogs }) {
  const [sql, setSql] = useState(DEFAULT_SQL)
  const [rawRows, setRawRows] = useState([])
  const [resultRows, setResultRows] = useState([])
  const [columns, setColumns] = useState(SELECTABLE_COLUMNS)
  const [exportColumns, setExportColumns] = useState(KIBANA_EXPORT_COLUMNS)
  const [selectedLog, setSelectedLog] = useState(null)
  const [lastParsedSql, setLastParsedSql] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const loadingRef = useRef(false)

  const selectedName = selectedFirewall?.name || '없음'

  const stats = useMemo(() => {
    const total = resultRows.length
    const alert = resultRows.filter(
      (row) =>
        toText(getRowValue(row, 'event_type'), '').toLowerCase() === 'alert',
    ).length
    const flow = resultRows.filter(
      (row) =>
        toText(getRowValue(row, 'event_type'), '').toLowerCase() === 'flow',
    ).length
    const sources = new Set(
      resultRows
        .map((row) => toText(getRowValue(row, 'source_ip'), ''))
        .filter(Boolean),
    ).size

    return {
      total,
      alert,
      flow,
      sources,
    }
  }, [resultRows])

  const previewRows = useMemo(() => {
    return resultRows.slice(0, 100)
  }, [resultRows])

  const executeSql = async () => {
    if (!selectedFirewall || loadingRef.current) return

    try {
      loadingRef.current = true
      setLoading(true)
      setError('')

      const parsedSql = parseSql(sql)
      const serverParams = inferServerParams(
        parsedSql.conditions,
        parsedSql.limit,
      )

      const data = await fetchEventLogs(serverParams)
      const rows = Array.isArray(data?.rows) ? data.rows : []

      const clientRows = runClientSql(rows, parsedSql)

      setRawRows(rows)
      setResultRows(clientRows)
      setColumns(parsedSql.columns)
      setLastParsedSql(parsedSql)
      setExportColumns(
        Array.isArray(data?.exportColumns) && data.exportColumns.length > 0
          ? data.exportColumns
          : KIBANA_EXPORT_COLUMNS,
      )
    } catch (err) {
      setRawRows([])
      setResultRows([])
      setError(err.message || 'SQL 로그 검색 실패')
    } finally {
      loadingRef.current = false
      setLoading(false)
    }
  }

  const handleExportCsv = () => {
    downloadCsv(
      makeTimestampedFilename('kibana_sql_query_logs'),
      exportColumns,
      buildElasticExportRows(resultRows),
    )
  }

  const handleCopySql = async () => {
    try {
      await navigator.clipboard.writeText(sql)
    } catch {
      // clipboard 실패는 무시
    }
  }

  useEffect(() => {
    executeSql()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedFirewall])

  return (
    <div className="sql-log-page">
      <section className="sql-log-header sql-log-card">
        <div>
          <p className="sql-log-eyebrow">SQL Log Search</p>
          <h2>SQL 로그 검색</h2>
          <span>현재 대상: {selectedName}</span>
        </div>

        <div className="sql-log-actions">
          <button type="button" onClick={executeSql} disabled={loading}>
            {loading ? '실행 중...' : 'SQL 실행'}
          </button>

          <button
            type="button"
            className="csv"
            onClick={handleExportCsv}
            disabled={resultRows.length === 0}
          >
            CSV 내보내기
          </button>
        </div>
      </section>

      {error ? <div className="sql-log-error">에러: {error}</div> : null}

      <section className="sql-log-card sql-query-panel">
        <div className="sql-log-section-title">
          <div>
            <p>Query Editor</p>
            <h3>SQL 입력</h3>
          </div>

          <button type="button" onClick={handleCopySql}>
            SQL 복사
          </button>
        </div>

        <div className="sql-query-editor-wrap">
          <textarea
            className="sql-query-editor"
            value={sql}
            onChange={(e) => setSql(e.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="sql-query-help">
          <strong>지원 문법</strong>
          <span>
            SELECT 컬럼 FROM logs WHERE 필드 = '값' AND 필드 LIKE '값' ORDER BY
            필드 ASC/DESC LIMIT 숫자
          </span>
        </div>
      </section>

      <section className="sql-log-card sql-sample-panel">
        <div className="sql-log-section-title">
          <div>
            <p>Samples</p>
            <h3>샘플 SQL</h3>
          </div>
        </div>

        <div className="sql-sample-grid">
          {SQL_SAMPLES.map((sample) => (
            <button
              key={sample.title}
              type="button"
              onClick={() => setSql(sample.sql)}
            >
              <strong>{sample.title}</strong>
              <code>{sample.sql.replace(/\s+/g, ' ')}</code>
            </button>
          ))}
        </div>
      </section>

      <section className="sql-log-stats-grid">
        <article className="sql-log-stat-card">
          <span>검색 결과</span>
          <strong>{stats.total.toLocaleString()}</strong>
        </article>

        <article className="sql-log-stat-card">
          <span>Alert</span>
          <strong>{stats.alert.toLocaleString()}</strong>
        </article>

        <article className="sql-log-stat-card">
          <span>Flow</span>
          <strong>{stats.flow.toLocaleString()}</strong>
        </article>

        <article className="sql-log-stat-card">
          <span>출발지 IP</span>
          <strong>{stats.sources.toLocaleString()}</strong>
        </article>
      </section>

      <section className="sql-log-card">
        <div className="sql-log-section-title">
          <div>
            <p>Result</p>
            <h3>SQL 실행 결과</h3>
          </div>

          <span className="sql-log-count">
            {previewRows.length.toLocaleString()} /{' '}
            {resultRows.length.toLocaleString()}건
          </span>
        </div>

        {lastParsedSql ? (
          <div className="sql-executed-info">
            <span>서버 조회: {rawRows.length.toLocaleString()}건</span>
            <span>LIMIT: {lastParsedSql.limit}</span>
            <span>
              ORDER BY: {lastParsedSql.order.field}{' '}
              {lastParsedSql.order.direction}
            </span>
          </div>
        ) : null}

        <div className="sql-log-table-wrap">
          <table className="sql-log-table">
            <thead>
              <tr>
                {columns.map((column) => (
                  <th key={column}>{column}</th>
                ))}
                <th>상세</th>
              </tr>
            </thead>

            <tbody>
              {previewRows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length + 1} className="sql-log-empty">
                    검색 결과가 없습니다.
                  </td>
                </tr>
              ) : (
                previewRows.map((log, index) => (
                  <tr key={log.id || index}>
                    {columns.map((column) => (
                      <td key={`${log.id || index}-${column}`}>
                        {toText(getRowValue(log, column))}
                      </td>
                    ))}

                    <td>
                      <button
                        type="button"
                        className="sql-log-detail-button"
                        onClick={() => setSelectedLog(log)}
                      >
                        보기
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>

      <SqlResultModal log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  )
}

export default FirewallLogSqlSearchPage
