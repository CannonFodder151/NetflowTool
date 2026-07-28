import React, { useState, useEffect } from 'react'
import { get, formatBytes } from '../api'
import StatCard from '../components/StatCard'
import Tile from '../components/Tile'

export default function Dashboard() {
  const [ok, setOk] = useState(false)
  const [data, setData] = useState({})
  const [err, setErr] = useState('')

  useEffect(() => {
    get('/api/dashboard/stats').then(r => {
      if (r.ok) { r.json().then(setData); setOk(true) }
      else setErr('Failed to load')
    }).catch(e => setErr(e.message))
  }, [])

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Network Dashboard</h1>
        <p className="page-subtitle">NetFlow traffic, SNMP interfaces, FortiGate logs</p>
      </div>

      {err && <div className="login-error mb-4">{err}</div>}

      {/* Quick stats */}
      <div className="stat-grid">
        <StatCard label="Today" value={formatBytes(data.traffic_day || 0)} />
        <StatCard label="This Week" value={formatBytes(data.traffic_week || 0)} />
        <StatCard label="This Month" value={formatBytes(data.traffic_month || 0)} />
        <StatCard label="Total" value={formatBytes(data.total_traffic || 0)} />
      </div>

      {/* Log risk stats */}
      {data.fortigate_log_stats && (
        <div className="stat-grid">
          {Object.entries(data.fortigate_log_stats).map(([k, v]) => (
            <StatCard key={k} label={`${k.toUpperCase()} Events`} value={v} />
          ))}
        </div>
      )}

      <div className="dashboard-grid">
        <Tile title="Top Talkers" span={6}>
          {data.top_talkers && data.top_talkers.length > 0 ? (
            <table className="table">
              <thead><tr><th>IP</th><th style={{textAlign:'right'}}>Bytes</th></tr></thead>
              <tbody>
                {data.top_talkers.map((t, i) => (
                  <tr key={i}><td className="text-sm">{t.ip}</td><td style={{textAlign:'right'}}>{formatBytes(t.bytes)}</td></tr>
                ))}
              </tbody>
            </table>
          ) : <p className="text-gray text-center py-4">No data</p>}
        </Tile>

        <Tile title="Top Services" span={6}>
          {data.top_services && data.top_services.length > 0 ? (
            <table className="table">
              <thead><tr><th>Service</th><th>Port</th><th style={{textAlign:'right'}}>Bytes</th></tr></thead>
              <tbody>
                {data.top_services.map((s, i) => (
                  <tr key={i}>
                    <td className="font-medium">{s.service}</td>
                    <td className="text-gray">{s.port}</td>
                    <td style={{textAlign:'right'}}>{formatBytes(s.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="text-gray text-center py-4">No data</p>}
        </Tile>

        <Tile title="Bandwidth Usage (Day / Week / Month)" span={12}>
          <div className="flex justify-between">
            <StatCard label="Day" value={formatBytes(data.traffic_day || 0)} />
            <StatCard label="Week" value={formatBytes(data.traffic_week || 0)} />
            <StatCard label="Month" value={formatBytes(data.traffic_month || 0)} />
          </div>
        </Tile>

        <Tile title="High Risk Changes" span={12}>
          {data.recent_changes && data.recent_changes.length > 0 ? (
            <table className="table">
              <thead><tr><th>Time</th><th>Device</th><th>Action</th><th>Message</th><th>Risk</th></tr></thead>
              <tbody>
                {data.recent_changes.map((c, i) => (
                  <tr key={i}>
                    <td className="text-xs">{c.ts}</td>
                    <td>{c.device}</td>
                    <td>{c.action}</td>
                    <td className="text-sm">{c.message}</td>
                    <td><span className={`badge badge-${c.risk === 'critical' ? 'red' : 'yellow'}`}>{c.risk}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="text-gray text-center py-4">No recent changes</p>}
        </Tile>
      </div>
    </>
  )
}