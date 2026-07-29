import React, { useState, useEffect } from 'react'
import { get, formatBytes, timeAgo } from '../api'
import Tile from '../components/Tile'

export default function Interfaces() {
  const [ifaces, setIfaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    get('/api/interfaces').then(r => r.ok && r.json().then(data => setIfaces(Array.isArray(data) ? data : []))).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const filtered = ifaces.filter(i =>
    i.name?.toLowerCase().includes(filter.toLowerCase()) ||
    i.device_name?.toLowerCase().includes(filter.toLowerCase()) ||
    i.device_ip?.includes(filter)
  )

  if (loading) return <Tile title="Interfaces" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <div className="dashboard-grid">
      <Tile title="All Interfaces" span={12}>
        <div className="mb-4">
          <input type="text" placeholder="Search..." value={filter} onChange={e => setFilter(e.target.value)} className="input w-full max-w-xs" />
        </div>
        <div className="overflow-x-auto">
          <table className="table">
            <thead><tr><th>Device</th><th>Interface</th><th>Speed</th><th>Admin</th><th>Oper</th><th>In</th><th>Out</th><th>Updated</th></tr></thead>
            <tbody>{filtered.map(i => (
              <tr key={i.id}>
                <td><strong>{i.device_name}</strong><br /><span className="text-xs text-gray">{i.device_ip}</span></td>
                <td className="font-mono">{i.name}</td>
                <td>{formatBytes(i.speed)}ps</td>
                <td><span className={`badge ${i.admin_status===1?'badge-green':'badge-red'}`}>{i.admin_status===1?'Up':'Down'}</span></td>
                <td><span className={`badge ${i.oper_status===1?'badge-green':'badge-red'}`}>{i.oper_status===1?'Up':'Down'}</span></td>
                <td>{formatBytes(i.in_octets)}</td>
                <td>{formatBytes(i.out_octets)}</td>
                <td className="text-xs text-gray">{timeAgo(i.last_updated)}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        {filtered.length === 0 && <p className="text-center py-4 text-gray">No interfaces found</p>}
      </Tile>
    </div>
  )
}