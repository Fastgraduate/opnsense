import LiveLogWorkspace from '../components/logs/LiveLogWorkspace'

export default function SecurityAlertsPage({ selectedFirewall, onAppLog }) {
  return <LiveLogWorkspace key={selectedFirewall?.id || 'none'} selectedFirewall={selectedFirewall} mode="attacks" onAppLog={onAppLog} />
}
