import React, { useState } from 'react'
import { useAuth } from '../context/AuthContext'

export default function PasswordReset() {
  const { user, changePassword } = useAuth()
  const [oldPass, setOldPass] = useState('')
  const [newPass, setNewPass] = useState('')
  const [confirmPass, setConfirmPass] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    
    if (newPass !== confirmPass) {
      setError('Passwords do not match')
      return
    }
    if (newPass.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }

    setLoading(true)
    try {
      await changePassword(oldPass, newPass)
      setSuccess(true)
    } catch (err) {
      setError(err.message || 'Failed to change password')
    } finally {
      setLoading(false)
    }
  }

  if (success) {
    return (
      <div className="login-container">
        <div className="login-card">
          <h1 className="login-title">Password Changed</h1>
          <p className="login-subtitle">Your password has been updated successfully.</p>
          <div className="text-center">
            <button className="btn btn-primary" onClick={() => window.location.href = '/'}>
              Continue to Dashboard
            </button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <h1 className="login-title">Reset Password</h1>
        <p className="login-subtitle">Please change your password before continuing</p>
        
        {error && <div className="login-error">{error}</div>}
        
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="label" htmlFor="old">Current Password</label>
            <input
              className="input"
              id="old"
              type="password"
              value={oldPass}
              onChange={e => setOldPass(e.target.value)}
              required
              autoComplete="current-password"
            />
          </div>
          <div className="form-group">
            <label className="label" htmlFor="new">New Password</label>
            <input
              className="input"
              id="new"
              type="password"
              value={newPass}
              onChange={e => setNewPass(e.target.value)}
              required
              minLength={8}
              autoComplete="new-password"
            />
          </div>
          <div className="form-group">
            <label className="label" htmlFor="confirm">Confirm New Password</label>
            <input
              className="input"
              id="confirm"
              type="password"
              value={confirmPass}
              onChange={e => setConfirmPass(e.target.value)}
              required
              autoComplete="new-password"
            />
          </div>
          <button type="submit" className="btn btn-primary login-btn" disabled={loading}>
            {loading ? 'Changing...' : 'Change Password'}
          </button>
        </form>
      </div>
    </div>
  )
}