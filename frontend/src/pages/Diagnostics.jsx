import React, { useState, useEffect } from 'react'
import { get, post } from '../api'
import Tile from '../components/Tile'

export default function Diagnostics() {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [clearing, setClearing] = useState(false)
  const [message, setMessage] = useState('')

  const load = () => {
    get('/api/system/status').then(r => r.ok && r.json().then(setStatus)).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  const handleClear = async () => {
    if (!confirm('This will delete ALL collected data (flows, interfaces, logs, dashboard layout). User accounts and device configs are kept. Continue?')) return
    setClearing(true)
    setMessage('')
    try {
      const res = await post('/api/system/clear', {})
      if (res.ok) {
        setMessage('All data cleared successfully')
        load()
      } else {
        setMessage('Failed to clear data')
      }
    } catch (e) {
      setMessage('Error: ' + e.message)
    } finally {
      setClearing(false)
    }
  }

  if (loading) return <Tile title="Diagnostics" span={12}><div className="text-center py-8">Loading...</div></Tile>

  const rows = [
    { label: 'Flow Records', val: status?.flow_records, desc: 'NetFlow v9/IPFIX data received on UDP 2055' },
    { label: 'Interfaces', val: status?.interfaces, desc: 'Interfaces polled via SNMP from configured devices' },
    { label: 'FortiGate Logs', val: status?.fortigate_logs, desc: 'Syslog messages received on port 514' },
    { label: 'SNMP Devices', val: status?.snmp_devices, desc: 'Devices configured for polling (kept on clear)' },
  ]

  return (
    <>
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title">Diagnostics</h1>
          <p className="page-subtitle">System status and data management</p>
        </div>
        <button className="btn btn-danger" onClick={handleClear} disabled={clearing}>
          {clearing ? 'Clearing...' : 'Clear All Data'}
        </button>
      </div>

      {message && <div className="mb-4 p-3 rounded" style={{ background: message.includes('Error') || message.includes('Failed') ? '#fef2f2' : '#dcfce7', border: `1px solid ${message.includes('Error') || message.includes('Failed') ? '#fecaca' : '#86efac'}`, color: message.includes('Error') || message.includes('Failed') ? '#991b1b' : '#166534' }}>{message}</div>}

      <div className="dashboard-grid">
        <Tile title="Data Collection Status" span={12}>
          <table className="table">
            <thead><tr><th>Data Source</th><th style={{textAlign:'right'}}>Count</th><th>Description</th></tr></thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.label}>
                  <td className="font-medium">{r.label}</td>
                  <td style={{textAlign:'right'}}>
                    <span className={`badge ${r.val > 0 ? 'badge-green' : 'badge-red'}`}>{r.val}</span>
                  </td>
                  <td className="text-sm text-gray">{r.desc}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {status && status.flow_records === 0 && status.interfaces === 0 && status.fortigate_logs === 0 && (
            <div className="mt-4 p-3 rounded" style={{ background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b' }}>
              No data is being collected. Configure NetFlow export, add SNMP devices and scan, and send FortiGate syslog to this server.
            </div>
          )}
        </Tile>
      </div>
    </>
  )
}