import { useEffect, useState } from 'react'
import './App.css'

interface FlowRecord {
  uid: string
  ts: number
  src_ip: string
  src_port: number
  dst_ip: string
  dst_port: number
  proto: string
  service: string | null
  duration: number | null
  orig_bytes: number | null
  resp_bytes: number | null
  conn_state: string | null
  seq: number
}

const API_BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8000'

function App() {
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const res = await fetch(`${API_BASE}/api/flows?limit=20`)
        if (res.ok) {
          const data: FlowRecord[] = await res.json()
          setFlows(data)
          setError(null)
        }
      } catch {
        setError('API not available')
      }
    }

    fetchFlows()
    const interval = setInterval(fetchFlows, 2000) // FE-3: throttled updates
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-6">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-emerald-400">SENTINEL-X</h1>
        <p className="text-gray-400 text-sm mt-1">Passive Network Threat Detection</p>
      </header>

      {/* FE-4: passivity status placeholder */}
      <div className="mb-6 flex gap-4 text-sm">
        <span className="px-3 py-1 rounded bg-emerald-900/50 text-emerald-300 border border-emerald-800">
          TX: 0 (passive)
        </span>
        <span className="px-3 py-1 rounded bg-gray-800 text-gray-300 border border-gray-700">
          Flows: {flows.length}
        </span>
      </div>

      {error && (
        <div className="mb-4 px-4 py-2 rounded bg-yellow-900/30 text-yellow-300 border border-yellow-800 text-sm">
          {error} — start the API with: uvicorn api.main:app
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-sm border-collapse">
          <thead>
            <tr className="text-left text-gray-400 border-b border-gray-800">
              <th className="pb-2 pr-4">Seq</th>
              <th className="pb-2 pr-4">Time</th>
              <th className="pb-2 pr-4">Source</th>
              <th className="pb-2 pr-4">Destination</th>
              <th className="pb-2 pr-4">Proto</th>
              <th className="pb-2 pr-4">Service</th>
              <th className="pb-2 pr-4">State</th>
              <th className="pb-2 pr-4">Bytes ↑</th>
              <th className="pb-2">Bytes ↓</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((f) => (
              <tr key={f.uid + f.seq} className="border-b border-gray-900 hover:bg-gray-900/50">
                <td className="py-1.5 pr-4 text-gray-500">{f.seq}</td>
                <td className="py-1.5 pr-4 font-mono text-xs">
                  {new Date(f.ts * 1000).toISOString().slice(11, 23)}
                </td>
                <td className="py-1.5 pr-4 font-mono">{f.src_ip}:{f.src_port}</td>
                <td className="py-1.5 pr-4 font-mono">{f.dst_ip}:{f.dst_port}</td>
                <td className="py-1.5 pr-4 uppercase">{f.proto}</td>
                <td className="py-1.5 pr-4">{f.service ?? '—'}</td>
                <td className="py-1.5 pr-4">{f.conn_state ?? '—'}</td>
                <td className="py-1.5 pr-4 text-right">{f.orig_bytes ?? '—'}</td>
                <td className="py-1.5 text-right">{f.resp_bytes ?? '—'}</td>
              </tr>
            ))}
            {flows.length === 0 && (
              <tr>
                <td colSpan={9} className="py-8 text-center text-gray-600">
                  No flows yet — replay traffic to see data
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default App
