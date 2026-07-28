import React, { useState, useEffect } from 'react'
import { get, post, del } from '../api'
import Tile from '../components/Tile'

export default function AdminDevices() {
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({
    name: '', ip: '', snmp_version: 'v2c', community: 'public',
    poll_interval: 60, enabled: true
  })

  useEffect(() => {
    get('/api/devices').then(r => r.ok && r.json().then(setDevices)).finally(() => setLoading(false))
  }, [])

  const resetForm = () => setForm({ name: '', ip: '', snmp_version: 'v2c', community: 'public', poll_interval: 60, enabled: true })

  const handleSubmit = async (e) => {
    e.preventDefault()
    const res = await fetch(editing ? `/api/devices/${editing.id}` : '/api/devices', {
      method: editing ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(form)
    })
    if (res.ok) { setShowModal(false); resetForm(); setEditing(null); get('/api/devices').then(r => r.ok && r.json().then(setDevices)) }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this device?')) return
    const res = await del(`/api/devices/${id}`)
    if (res.ok) get('/api/devices').then(r => r.ok && r.json().then(setDevices))
  }

  if (loading) return <Tile title="SNMP Devices" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title">SNMP Devices</h1>
          <p className="page-subtitle">Configure firewalls and switches for interface polling</p>
        </div>
        <button className="btn btn-primary" onClick={() => { resetForm(); setShowModal(true) }}>Add Device</button>
      </div>

      <Tile title="Configured Devices" span={12}>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>IP</th>
                <th>Version</th>
                <th>Community</th>
                <th>Poll (s)</th>
                <th>Status</th>
                <th>Last Poll</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map(d => (
                <tr key={d.id}>
                  <td className="font-medium">{d.name}</td>
                  <td className="font-mono">{d.ip}</td>
                  <td><span className="badge badge-blue">{d.snmp_version.toUpperCase()}</span></td>
                  <td className="font-mono text-sm">{d.community}</td>
                  <td>{d.poll_interval}</td>
                  <td><span className={d.enabled ? 'badge badge-green' : 'badge badge-red'}>{d.enabled ? 'Enabled' : 'Disabled'}</span></td>
                  <td className="text-sm">{d.last_poll ? format(new Date(d.last_poll), 'MMM d, HH:mm') : 'Never'}</td>
                  <td>
                    <div className="flex gap-2">
                      <button className="btn btn-sm btn-outline" onClick={() => { setForm(d); setEditing(d); setShowModal(true) }}>Edit</button>
                      <button className="btn btn-sm btn-outline btn-danger" onClick={() => handleDelete(d.id)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Tile>

      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => { setShowModal(false); resetForm(); setEditing(null) }}>
          <div className="bg-white rounded-lg p-6 w-full max-w-md" onClick={e => e.stopPropagation()}>
            <h2 className="text-xl font-semibold mb-4">{editing ? 'Edit Device' : 'Add Device'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="mb-3">
                <label className="label">Name</label>
                <input type="text" value={form.name} onChange={e => setForm({...form, name: e.target.value})} className="input" required />
              </div>
              <div className="mb-3">
                <label className="label">IP Address</label>
                <input type="text" value={form.ip} onChange={e => setForm({...form, ip: e.target.value})} className="input" required />
              </div>
              <div className="mb-3">
                <label className="label">SNMP Version</label>
                <select value={form.snmp_version} onChange={e => setForm({...form, snmp_version: e.target.value})} className="input">
                  <option value="v2c">v2c</option>
                  <option value="v3">v3</option>
                </select>
              </div>
              <div className="mb-3">
                <label className="label">Community (v2c)</label>
                <input type="text" value={form.community} onChange={e => setForm({...form, community: e.target.value})} className="input" />
              </div>
              <div className="mb-3">
                <label className="label">Poll Interval (seconds)</label>
                <input type="number" value={form.poll_interval} onChange={e => setForm({...form, poll_interval: parseInt(e.target.value)})} className="input" min="10" max="3600" />
              </div>
              <div className="mb-4">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={form.enabled} onChange={e => setForm({...form, enabled: e.target.checked})} className="w-4 h-4" />
                  Enabled
                </label>
              </div>
              <div className="flex gap-3 justify-end">
                <button type="button" className="btn btn-outline" onClick={() => { setShowModal(false); resetForm(); setEditing(null) }}>Cancel</button>
                <button type="submit" className="btn btn-primary">{editing ? 'Save' : 'Add'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
