import React, { useState, useEffect } from 'react'
import { get, post, del } from '../api'
import Tile from '../components/Tile'
import { format } from 'date-fns'

export default function AdminUsers() {
  const [users, setUsers] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ username: '', password: '', is_admin: false })

  useEffect(() => {
    get('/api/users').then(r => r.ok && r.json().then(setUsers)).finally(() => setLoading(false))
  }, [])

  const resetForm = () => setForm({ username: '', password: '', is_admin: false })

  const handleSubmit = async (e) => {
    e.preventDefault()
    const url = editing ? `/api/users/${editing.id}` : '/api/users'
    const method = editing ? 'PUT' : 'POST'
    const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) })
    if (res.ok) { setShowModal(false); resetForm(); setEditing(null); get('/api/users').then(r => r.ok && r.json().then(setUsers)) }
  }

  const handleDelete = async (id) => {
    if (!confirm('Delete this user?')) return
    const res = await del(`/api/users/${id}`)
    if (res.ok) get('/api/users').then(r => r.ok && r.json().then(setUsers))
  }

  if (loading) return <Tile title="Users" span={12}><div className="text-center py-8">Loading...</div></Tile>

  return (
    <>
      <div className="page-header flex justify-between items-center">
        <div>
          <h1 className="page-title">User Management</h1>
          <p className="page-subtitle">Admin-only user administration</p>
        </div>
        <button className="btn btn-primary" onClick={() => { resetForm(); setShowModal(true) }}>Add User</button>
      </div>

      <Tile title="All Users" span={12}>
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Admin</th>
                <th>Must Reset</th>
                <th>Created</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td className="font-medium">{u.username}</td>
                  <td><span className={u.is_admin ? 'badge badge-green' : 'badge badge-gray'}>
                    {u.is_admin ? 'Yes' : 'No'}</span></td>
                  <td><span className={u.must_reset_password ? 'badge badge-yellow' : 'badge badge-green'}>
                    {u.must_reset_password ? 'Yes' : 'No'}</span></td>
                  <td>{u.created_at ? format(new Date(u.created_at), 'MMM d, yyyy') : '-'}</td>
                  <td>{u.last_login ? format(new Date(u.last_login), 'MMM d, yyyy HH:mm') : 'Never'}</td>
                  <td>
                    <div className="flex gap-2">
                      <button className="btn btn-sm btn-outline" onClick={() => { setForm({ username: u.username, password: '', is_admin: u.is_admin }); setEditing(u); setShowModal(true) }}>Edit</button>
                      {u.is_admin && <button className="btn btn-sm btn-outline" onClick={() => handleDelete(u.id)}>Delete</button>}
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
            <h2 className="text-xl font-semibold mb-4">{editing ? 'Edit User' : 'Create User'}</h2>
            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label className="block text-sm font-medium mb-1">Username</label>
                <input type="text" value={form.username} onChange={e => setForm({...form, username: e.target.value})} className="input w-full" required disabled={editing} />
              </div>
              {!editing && (
                <div className="mb-4">
                  <label className="block text-sm font-medium mb-1">Password</label>
                  <input type="password" value={form.password} onChange={e => setForm({...form, password: e.target.value})} className="input w-full" required minLength={4} />
                </div>
              )}
              <div className="mb-4">
                <label className="flex items-center gap-2">
                  <input type="checkbox" checked={form.is_admin} onChange={e => setForm({...form, is_admin: e.target.checked})} className="w-4 h-4" />
                  Admin
                </label>
              </div>
              <div className="flex gap-3 justify-end">
                <button type="button" className="btn btn-outline" onClick={() => { setShowModal(false); resetForm(); setEditing(null) }}>Cancel</button>
                <button type="submit" className="btn btn-primary">{editing ? 'Save' : 'Create'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </>
  )
}
