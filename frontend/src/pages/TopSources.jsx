import React, { useState, useEffect } from 'react'
import { get, formatBytes } from '../api'
import Tile from '../components/Tile'

export default function TopSources() {
  const [data, setData] = useState([])
  const [loading, setLoading] = useState(true)
  const [range, setRange] = useState('1h')

  useEffect(() => {
    get(`/api/flows/top-sources?range=${range}&limit=50`)
      .then(r => r.ok && r.json().then(setData))
      .finally(() => setLoading(false))
  }, [range])

  if (loading) return <Tile title="Top Sources" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Top Sources</h1>
        <p className="page-subtitle">Most active source IPs by connection count</p>
      </div>
      <div className="dashboard-grid">
        <Tile title="Top Sources" span={12}>
          <select value={range} onChange={e => setRange(e.target.value)} className="input w-auto mb-4">
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>#</th><th>Source IP</th><th>Connections</th><th style={{textAlign:'right'}}>Bytes</th></tr></thead>
              <tbody>{data.map((s, i) => (
                <tr key={i}>
                  <td>{i+1}</td>
                  <td className="font-mono font-medium">{s.ip}</td>
                  <td>{s.hits}</td>
                  <td style={{textAlign:'right'}}>{formatBytes(s.bytes)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          {data.length === 0 && <p className="text-center py-4 text-gray">No data for this period</p>}
        </Tile>
      </div>
    </>
  )
}