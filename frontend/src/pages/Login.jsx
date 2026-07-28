import React, { useState } from 'react'
import { useAuth } from '../context/AuthContext'

export default function Login() {
  const { login } = useAuth()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('admin')
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await login(username, password)
    } catch (err) {
      setError(err.message || 'Login failed')
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="text-center mb-8">
          <div className="text-4xl mb-2">📊</div>
          <h1 className="login-title">NetFlow Monitor</h1>
          <p className="login-subtitle">Sign in to access the dashboard</p>
        </div>

        {error && <div className="login-error" role="alert">{error}</div>}

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="label" htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              className="input"
              required
              autoComplete="username"
              autoFocus
            />
          </div>

          <div className="form-group">
            <label className="label" htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="input"
              required
              autoComplete="current-password"
            />
          </div>

          <button type="submit" className="btn btn-primary login-btn w-full">
            Sign In
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-gray">
          Default: <code className="bg-gray-100 px-1 rounded">admin</code> / <code className="bg-gray-100 px-1 rounded">admin</code> (forces password reset on first login)
        </p>
      </div>
    </div>
  )
}