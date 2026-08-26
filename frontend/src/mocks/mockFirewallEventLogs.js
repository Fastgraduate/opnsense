const interfaces = ['wan', 'lan', 'opt1', 'wlx3c64cf7410ca']
const protocols = ['TCP', 'UDP', 'ICMP']
const eventTypes = ['flow', 'alert', 'dns', 'http', 'tls']
const actions = ['inbound', 'outbound', 'alert', 'flow', 'dns', 'http', 'tls']
const categories = [
  'suricata.eve',
  'Potentially Bad Traffic',
  'Attempted Information Leak',
  'Misc activity',
  'DNS Query',
  'Web Traffic',
]
const hosts = ['opnsense-main', 'ubuntu-suricata', 'elastic-node-01']
const signatures = [
  'ET POLICY DNS Query for suspicious domain',
  'ET SCAN Potential SSH Scan',
  'ET WEB_SERVER Possible HTTP Probe',
  'SURICATA STREAM established',
  'SURICATA DNS query observed',
  'Allowed outbound traffic',
  'Blocked inbound connection',
]

const sourceIps = [
  '192.168.0.2',
  '192.168.0.10',
  '192.168.0.25',
  '10.0.0.5',
  '172.16.1.20',
  '203.0.113.10',
]

const destinationIps = [
  '8.8.8.8',
  '1.1.1.1',
  '61.81.107.7',
  '192.168.0.1',
  '192.168.44.141',
  '203.0.113.77',
]

const randomItem = (arr, index) => arr[index % arr.length]

const makeTimestamp = (index) => {
  const now = Date.now()
  const offsetMs = index * 45 * 1000
  return new Date(now - offsetMs).toISOString()
}

const makeMockLog = (index) => {
  const eventType = randomItem(eventTypes, index)
  const action = randomItem(actions, index)
  const protocol = randomItem(protocols, index)
  const srcIp = randomItem(sourceIps, index)
  const dstIp = randomItem(destinationIps, index + 2)
  const srcPort = protocol === 'ICMP' ? null : 10000 + index * 13
  const dstPort =
    protocol === 'ICMP'
      ? null
      : randomItem([22, 53, 80, 443, 9200, 5601, 8080], index)

  const severity = eventType === 'alert' ? randomItem([1, 2, 3], index) : '-'
  const category = randomItem(categories, index)
  const signature = randomItem(signatures, index)

  return {
    _index: `suricata-logstash-${new Date(makeTimestamp(index))
      .toISOString()
      .slice(0, 10)}`,
    _id: `mock-log-${index + 1}`,
    _score: 1,
    _source: {
      '@timestamp': makeTimestamp(index),
      event: {
        dataset: 'suricata.eve',
        module: 'suricata',
        category,
        severity,
      },
      host: {
        name: randomItem(hosts, index),
        hostname: randomItem(hosts, index),
        ip: ['192.168.0.2'],
        os: {
          name: 'Ubuntu',
          version: '22.04.5 LTS',
        },
      },
      network: {
        transport: protocol,
        direction: action,
      },
      source: {
        ip: srcIp,
        address: srcIp,
        port: srcPort,
      },
      destination: {
        ip: dstIp,
        address: dstIp,
        port: dstPort,
      },
      suricata: {
        eve: {
          event_type: eventType,
          in_iface: randomItem(interfaces, index),
          app_proto:
            dstPort === 53
              ? 'dns'
              : dstPort === 80
                ? 'http'
                : dstPort === 443
                  ? 'tls'
                  : '-',
          flow_id: String(900000000000 + index),
          alert:
            eventType === 'alert'
              ? {
                  signature,
                  category,
                  severity,
                }
              : undefined,
          flow:
            eventType === 'flow'
              ? {
                  state: 'established',
                  reason: 'timeout',
                  alerted: false,
                  pkts_toserver: 3 + index,
                  pkts_toclient: 2 + index,
                  bytes_toserver: 120 + index * 30,
                  bytes_toclient: 300 + index * 45,
                }
              : undefined,
        },
      },
      service: {
        type: 'suricata',
      },
      log: {
        file: {
          path: '/var/log/suricata/eve.json',
        },
      },
      tags: ['suricata', 'mock_data'],
    },
  }
}

export const createMockFirewallEventLogs = (filters = {}) => {
  const size = Number(filters.size || 200)
  const rows = Array.from({ length: Math.min(size, 500) }, (_, index) =>
    makeMockLog(index),
  )

  return {
    mock: true,
    rows,
    hits: {
      total: {
        value: rows.length,
        relation: 'eq',
      },
      hits: rows,
    },
  }
}
