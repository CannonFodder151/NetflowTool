import React, { useState, useEffect } from 'react'
import { get, formatBytes } from '../api'
import Tile from '../components/Tile'

export default function Services() {
  const [services, setServices] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    get('/api/flows/top-services?limit=50').then(r => r.ok && r.json().then(setServices))
      .finally(() => setLoading(false))
  }, [])

  const filtered = services.filter(s =>
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

      <Tile title="All Services" span={12}>
        <div className="flex gap-4 mb-4">
          <input
            type="text"
            placeholder="Search by service name or port..."
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="input w-full max-w-xs"
            aria-label="Filter services"
          />
        </div>

        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Service</th>
                <th>Port</th>
                <th>Bytes Transferred</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.port}>
                  <td className="font-medium">{s.service || "Unknown"}</td>
                  <td className="text-gray">{s.port || "-"}</td>
                  <td className="font-medium">{formatBytes(s.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Tile>
    </>
  )
}
