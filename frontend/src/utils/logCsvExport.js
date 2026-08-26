export const KIBANA_EXPORT_COLUMNS = [
  '@timestamp',
  '_id',
  '_index',
  '_score',
  '_type',
  'agent.ephemeral_id',
  'agent.hostname',
  'agent.id',
  'agent.name',
  'agent.type',
  'agent.version',
  'ecs.version',
  'host.name',
  'input.type',
  'log.file.path',
  'log.offset',
  'message',
]

export const OPN_LOG_EXPORT_COLUMNS = [
  'time',
  'interface',
  'direction',
  'protocol',
  'source',
  'destination',
  'action',
  'label',
  'raw',
]

export const getNestedValue = (data, path, fallback = '') => {
  if (!data || !path) return fallback

  const value = path.split('.').reduce((cur, key) => {
    if (cur == null || typeof cur !== 'object') return undefined
    return cur[key]
  }, data)

  return value ?? fallback
}

export const escapeCsvValue = (value) => {
  if (value === null || value === undefined) return ''

  const text =
    typeof value === 'object' ? JSON.stringify(value) : String(value)

  if (/[",\n\r]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`
  }

  return text
}

export const downloadCsv = (filename, columns, rows) => {
  const safeColumns = Array.isArray(columns) && columns.length > 0 ? columns : []
  const safeRows = Array.isArray(rows) ? rows : []

  const header = safeColumns.map(escapeCsvValue).join(',')
  const body = safeRows
    .map((row) =>
      safeColumns
        .map((column) => escapeCsvValue(row?.[column] ?? ''))
        .join(','),
    )
    .join('\n')

  const csv = `${header}\n${body}`
  const blob = new Blob(['\uFEFF' + csv], {
    type: 'text/csv;charset=utf-8;',
  })

  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')

  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)

  URL.revokeObjectURL(url)
}

export const buildElasticExportRows = (rows) => {
  const sourceRows = Array.isArray(rows) ? rows : []

  return sourceRows.map((row) => {
    if (row?.exportRow && typeof row.exportRow === 'object') {
      return row.exportRow
    }

    const raw = row?.raw && typeof row.raw === 'object' ? row.raw : {}

    return {
      '@timestamp': raw['@timestamp'] ?? row?.timestamp ?? '',
      _id: row?.id ?? '',
      _index: row?._index ?? '',
      _score: row?._score ?? '',
      _type: row?._type ?? '_doc',
      'agent.ephemeral_id': getNestedValue(raw, 'agent.ephemeral_id'),
      'agent.hostname': getNestedValue(raw, 'agent.hostname'),
      'agent.id': getNestedValue(raw, 'agent.id'),
      'agent.name': getNestedValue(raw, 'agent.name'),
      'agent.type': getNestedValue(raw, 'agent.type'),
      'agent.version': getNestedValue(raw, 'agent.version'),
      'ecs.version': getNestedValue(raw, 'ecs.version'),
      'host.name': getNestedValue(raw, 'host.name') || row?.host || '',
      'input.type': getNestedValue(raw, 'input.type'),
      'log.file.path': getNestedValue(raw, 'log.file.path'),
      'log.offset': getNestedValue(raw, 'log.offset'),
      message: raw.message ?? row?.message ?? JSON.stringify(raw || row || {}),
    }
  })
}

export const buildOpnsenseExportRows = (rows) => {
  const sourceRows = Array.isArray(rows) ? rows : []

  return sourceRows.map((row) => ({
    time: row?.time ?? row?.timestamp ?? '',
    interface: row?.interface ?? '',
    direction: row?.direction ?? '',
    protocol: row?.protocol ?? '',
    source: row?.source ?? row?.source_ip ?? '',
    destination: row?.destination ?? row?.destination_ip ?? '',
    action: row?.action ?? '',
    label: row?.label ?? row?.rule ?? row?.description ?? '',
    raw: JSON.stringify(row?.raw ?? row ?? {}),
  }))
}

export const makeTimestampedFilename = (prefix) => {
  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, '-')
    .replace('T', '_')
    .slice(0, 19)

  return `${prefix}_${stamp}.csv`
}
