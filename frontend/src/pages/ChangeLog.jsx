import React, { useState, useEffect } from 'react'
import { get, timeAgo } from '../api'
import Tile from '../components/Tile'

export default function ChangeLog() {
  const [logs, setLogs] = useState([])
  const [allLogs, setAllLogs] = useState([])
  const [loading, setLoading] = useState(true)
  const [riskFilter, setRiskFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')

  useEffect(() => {
    Promise.all([
      get('/api/fortigate/changelog'),
      get('/api/fortigate/logs?limit=200')
    ]).then(async ([chRes, logsRes]) => {
      if (chRes.ok) setLogs(await chRes.json())
      if (logsRes.ok) setAllLogs(await logsRes.json())
    }).finally(() => setLoading(false))
  }, [])

  const filtered = allLogs.filter(l => {
    if (riskFilter && l.risk_level !== riskFilter) return false
    if (actionFilter && l.action !== actionFilter) return false
    return true
  })

  if (loading) return <Tile title="Change Log" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Change Log & Security Events</h1>
        <p className="page-subtitle">FortiGate log ingestion - high risk actions flagged</p>
      </div>

      <Tile title="High Risk Events" span={12}>
        {logs.length > 0 ? (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Device</th>
                <th>Action</th>
                <th>Message</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((l, i) => (
                <tr key={i}>
                  <td className="text-sm">{l.timestamp || l.ts}</td>
                  <td>{l.device}</td>
                  <td>{l.action}</td>
                  <td className="max-w-md">{l.message}</td>
                  <td><span className={`badge ${(l.risk || l.risk_level) === 'critical' ? 'badge-red' : 'badge-yellow'}`}>{l.risk || l.risk_level}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="text-gray text-center py-8">No high risk events</p>}
      </Tile>

      <Tile title="All Logs" span={12}>
        <div className="flex gap-4 mb-4">
          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} className="input w-auto">
            <option value="">All Risks</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
          <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} className="input w-auto">
            <option value="">All Actions</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="drop">Drop</option>
          </select>
          <span className="text-sm text-gray self-center">{filtered.length} logs</span>
        </div>
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Device</th>
                <th>Type</th>
                <th>Action</th>
                <th>Src</th>
                <th>Dst</th>
                <th>Service</th>
                <th>Message</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((l, i) => (
                <tr key={i}>
                  <td className="text-xs">{l.timestamp}</td>
                  <td>{l.device_ip}</td>
                  <td><span className="badge badge-gray">{l.log_type}</span></td>
                  <td className="font-medium">{l.action}</td>
                  <td className="font-mono text-xs">{l.src_ip}</td>
                  <td className="font-mono text-xs">{l.dst_ip}</td>
                  <td>{l.service}</td>
                  <td className="max-w-xs truncate">{l.message}</td>
                  <td><span className={`badge badge-${l.risk_level === 'critical' ? 'red' : l.risk_level === 'high' ? 'red' : l.risk_level === 'medium' ? 'yellow' : 'green'}`}>{l.risk_level}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Tile>
    </>
  )
}
