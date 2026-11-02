import LiveLogWorkspace from '../components/logs/LiveLogWorkspace'

export default function OpnsenseFirewallLogsPage({ selectedFirewall, onAppLog }) {
  return <LiveLogWorkspace key={selectedFirewall?.id || 'none'} selectedFirewall={selectedFirewall} mode="opnsense" onAppLog={onAppLog} />
}
