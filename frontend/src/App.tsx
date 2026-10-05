import { useEffect, useMemo, useState } from 'react'
import './App.css'

type Flow = {
  uid: string; seq: number; ts_start: number; src_ip: string; src_port: number
  dst_ip: string; dst_port: number; proto: string; service: string | null
  conn_state: string | null; orig_bytes: number | null; resp_bytes: number | null
}
type Alert = {
  alert_id: string; timestamp: string; source_ip: string; threat_class: string
  severity: string; confidence: number; attack_technique: string; detector_version: string
  evidence_hash: string; prev_hash: string; evidence: Record<string, unknown>
  explanation: { signal: string; contribution: number; details?: string }[]
}
type Stats = { flow_count: number; alert_count: number; threat_counts: Record<string, number>; passivity: { tx_packets: number; status: string; mode: string; interface: string | null }; visibility_health: number }

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

function App() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [stats, setStats] = useState<Stats>({ flow_count: 0, alert_count: 0, threat_counts: {}, passivity: { tx_packets: 0, status: 'emulated', mode: 'software-emulation', interface: null }, visibility_health: 1 })
  const [selected, setSelected] = useState<Alert | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [resetting, setResetting] = useState(false)

  const refresh = async () => {
    try {
      const [flowResponse, alertResponse, statsResponse] = await Promise.all([
        fetch(`${API_BASE}/api/flows?limit=30`), fetch(`${API_BASE}/api/alerts`), fetch(`${API_BASE}/api/stats`),
      ])
      setFlows(await flowResponse.json()); setAlerts(await alertResponse.json()); setStats(await statsResponse.json()); setError(null)
    } catch { setError('API unavailable — start it with: uvicorn api.main:app --reload') }
  }
  useEffect(() => {
    refresh()
    const timer = setInterval(refresh, 2000)
    const socket = new WebSocket(API_BASE.replace('http', 'ws') + '/api/ws')
    socket.onmessage = () => refresh()
    return () => { clearInterval(timer); socket.close() }
  }, [])

  const resetDemo = async () => {
    setResetting(true)
    try {
      await fetch(`${API_BASE}/api/demo/reset`, { method: 'POST' })
      setSelected(null)
      await refresh()
    } catch {
      setError('Could not reset the demo')
    } finally {
      setResetting(false)
    }
  }

  const threatSummary = useMemo(() => Object.entries(stats.threat_counts), [stats.threat_counts])
  return (
    <main className="shell">
      <header className="header">
        <div><p className="eyebrow">PASSIVE NETWORK TELEMETRY</p><h1>SENTINEL<span>-X</span></h1><p className="muted">Phase 1 detection console · metadata only · software-emulated passive monitoring demo</p></div>
        <div className="header-actions"><div className={`attestation ${stats.passivity.status}`}><b>● {stats.passivity.status === 'verified' ? 'PASSIVITY VERIFIED' : 'PASSIVITY EMULATED'}</b><small>TX packets: {stats.passivity.tx_packets} · {stats.passivity.mode}</small></div><button className="reset" onClick={resetDemo} disabled={resetting}>{resetting ? 'RESETTING…' : 'RESET DEMO'}</button></div>
      </header>
      <section className="mission">
        <div><b>THE ONE-WAY NETWORK PROBLEM</b><p>Conventional IDS tools assume they can communicate back. SENTINEL-X treats the monitoring enclave as receive-only and makes its confidence explainable.</p></div>
        <div className="pillars"><span>PASSIVITY PROOF</span><span>VISIBILITY HEALTH</span><span>HASH-CHAINED EVIDENCE</span></div>
      </section>
      <section className="metrics">
        <Metric label="Flows observed" value={stats.flow_count} />
        <Metric label="Active alerts" value={stats.alert_count} accent />
        <Metric label="Visibility health" value={`${Math.round(stats.visibility_health * 100)}%`} />
        <Metric label="Threat classes" value={threatSummary.length} />
      </section>
      {error && <div className="notice">{error}</div>}
      <section className="grid">
        <div className="panel"><div className="panel-title"><h2>Live flow stream</h2><span>RECENT 30</span></div>
          <div className="table-wrap"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>STATE</th></tr></thead><tbody>
            {flows.map((flow) => <tr key={`${flow.uid}-${flow.seq}`}><td>{new Date(flow.ts_start * 1000).toISOString().slice(11, 19)}</td><td>{flow.src_ip}:{flow.src_port}</td><td>{flow.dst_ip}:{flow.dst_port}</td><td>{flow.proto.toUpperCase()}</td><td>{flow.conn_state ?? '—'}</td></tr>)}
            {!flows.length && <tr><td colSpan={5} className="empty">No flows yet. Run the seeded replay.</td></tr>}
          </tbody></table></div>
        </div>
        <div className="panel"><div className="panel-title"><h2>Detections</h2><span>{alerts.length} TOTAL</span></div>
          {alerts.map((alert) => <button className={`alert ${alert.severity.toLowerCase()}`} key={alert.alert_id} onClick={() => setSelected(alert)}><div><b>{alert.threat_class.replace('_', ' ')}</b><small>{alert.source_ip} · {new Date(alert.timestamp).toLocaleTimeString()}</small></div><strong>{Math.round(alert.confidence * 100)}%</strong></button>)}
          {!alerts.length && <p className="empty">No alerts. Benign traffic should remain quiet.</p>}
        </div>
      </section>
      {selected && <section className="panel detail"><div className="panel-title"><h2>{selected.threat_class.replace('_', ' ')} evidence</h2><button onClick={() => setSelected(null)}>CLOSE</button></div><p><b>Source:</b> {selected.source_ip} · <b>Confidence:</b> {Math.round(selected.confidence * 100)}% · <b>ATT&CK:</b> {selected.attack_technique} · <b>Detector:</b> {selected.detector_version}</p><pre>{JSON.stringify({ evidence: selected.evidence, explanation: selected.explanation, evidence_hash: selected.evidence_hash, prev_hash: selected.prev_hash }, null, 2)}</pre></section>}
      <footer className="footer">SENTINEL-X · receive-only by design · payloads are never inspected or decrypted · demo state is in memory</footer>
    </main>
  )
}
function Metric({ label, value, accent = false }: { label: string; value: string | number; accent?: boolean }) {
  return <div className={`metric ${accent ? 'accent' : ''}`}><small>{label}</small><b>{value}</b></div>
}
export default App
