import React, { useState, useEffect } from 'react'
import { get, formatBytes } from '../api'
import Tile from '../components/Tile'

export default function Services() {
  const [svcs, setSvcs] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    get('/api/flows/top-services?limit=50').then(r => r.ok && r.json().then(setSvcs))
      .finally(() => setLoading(false))
  }, [])

  const filtered = svcs.filter(s =>
    s.service?.toLowerCase().includes(filter.toLowerCase()) ||
    s.port?.toString().includes(filter)
  )

  if (loading) return <Tile title="Services" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Services</h1>
        <p className="page-subtitle">Top network services by traffic volume</p>
      </div>
      <div className="dashboard-grid">
        <Tile title="All Services" span={12}>
          <input type="text" placeholder="Search by name or port..." value={filter} onChange={e => setFilter(e.target.value)} className="input w-full max-w-xs mb-4" />
          <div className="overflow-x-auto">
            <table className="table">
              <thead><tr><th>Service</th><th>Port</th><th style={{textAlign:'right'}}>Bytes</th></tr></thead>
              <tbody>{filtered.map((s, i) => (
                <tr key={s.port || i}>
                  <td className="font-medium">{s.service || "Unknown"}</td>
                  <td className="text-gray">{s.port || "-"}</td>
                  <td style={{textAlign:'right'}}>{formatBytes(s.bytes)}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
          {filtered.length === 0 && <p className="text-center py-4 text-gray">No services data</p>}
        </Tile>
      </div>
    </>
  )
}