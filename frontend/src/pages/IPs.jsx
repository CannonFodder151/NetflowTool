import React, { useState, useEffect } from 'react'
import { get, formatBytes } from '../api'
import Tile from '../components/Tile'

export default function IPs() {
  const [ips, setIps] = useState([])
  const [loading, setLoading] = useState(true)
  const [range, setRange] = useState('1h')

  useEffect(() => {
    get(`/api/flows/top-talkers?range=${range}&limit=50`)
      .then(r => r.ok && r.json().then(setIps))
      .finally(() => setLoading(false))
  }, [range])

  if (loading) return <Tile title="IP Addresses" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">IP Addresses</h1>
        <p className="page-subtitle">Top talkers by traffic volume</p>
      </div>
      <div className="dashboard-grid">
        <Tile title="Top Talkers" span={12}>
          <select value={range} onChange={e => setRange(e.target.value)} className="input w-auto mb-4">
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>#</th><th>IP Address</th><th>Bytes</th></tr></thead>
              <tbody>{ips.map((ip, i) => (
                <tr key={i}>
                  <td className="text-gray">{i+1}</td>
                  <td className="font-mono font-medium">{ip.ip}</td>
                  <td className="font-medium">{formatBytes(ip.bytes)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          {ips.length === 0 && <p className="text-center py-4 text-gray">No data for this period</p>}
        </Tile>
      </div>
    </>
  )
}