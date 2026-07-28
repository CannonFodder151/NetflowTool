import React, { useState, useEffect } from 'react'
import { get, formatBytes, timeAgo } from '../api'
import Tile from '../components/Tile'
import Table from '../components/Table'

export default function Interfaces() {
  const [ifaces, setIfaces] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    get('/api/interfaces').then(r => r.ok && r.json().then(setIfaces)).finally(() => setLoading(false))
  }, [])

  const filtered = ifaces.filter(i =>
    i.name?.toLowerCase().includes(filter.toLowerCase()) ||
    i.device_name?.toLowerCase().includes(filter.toLowerCase()) ||
    i.device_ip?.includes(filter)
  )

  if (loading) return <Tile title="Interfaces" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Network Interfaces</h1>
        <p className="page-subtitle">SNMP polled interfaces from configured devices</p>
      </div>

      <Tile title="All Interfaces" span={12}>
        <div className="mb-4">
          <input
            type="text"
            placeholder="Search by name, device, IP..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="input w-full max-w-xs"
            aria-label="Filter interfaces"
          />
        </div>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Interface</th>
                <th>Description</th>
                <th>Speed</th>
                <th>Admin</th>
                <th>Oper</th>
                <th>In (Bytes)</th>
                <th>Out (Bytes)</th>
                <th>Errors</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(i => (
                <tr key={i.id}>
                  <td>
                    <div className="font-medium">{i.device_name}</div>
                    <div className="text-xs text-gray">{i.device_ip}</div>
                  </td>
                  <td className="font-mono text-sm">{i.name}</td>
                  <td className="text-sm">{i.description || '-'}</td>
                  <td>{formatBytes(i.speed)}ps</td>
                  <td><span className={`badge ${i.admin_status === 1 ? 'badge-green' : 'badge-red'}`}>
                    {i.admin_status === 1 ? 'Up' : 'Down'}</span></td>
                  <td><span className={`badge ${i.oper_status === 1 ? 'badge-green' : 'badge-red'}`}>
                    {i.oper_status === 1 ? 'Up' : 'Down'}</span></td>
                  <td>{formatBytes(i.in_octets)}</td>
                  <td>{formatBytes(i.out_octets)}</td>
                  <td className="text-red-600">{i.in_errors + i.out_errors}</td>
                  <td className="text-xs text-gray">{timeAgo(i.last_updated)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Tile>
    </>
  )
}
