import LiveLogWorkspace from '../components/logs/LiveLogWorkspace'

export default function FirewallEventLogsPage({ selectedFirewall, onAppLog }) {
  return <LiveLogWorkspace key={selectedFirewall?.id || 'none'} selectedFirewall={selectedFirewall} mode="events" onAppLog={onAppLog} />
}
