import React, { createContext, useContext, useState, useEffect } from 'react'
import { get, post } from '../api'

const AuthContext = createContext()

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [mustReset, setMustReset] = useState(false)
  const [ready, setReady] = useState(false)

  const checkLogin = () => {
    const token = localStorage.getItem('token')
    if (!token) { setReady(true); return }
    get('/api/me').then(r => {
      if (r.ok) { r.json().then(d => { setUser({ ...d, isAdmin: d.is_admin }); setReady(true) }) }
      else { localStorage.removeItem('token'); setReady(true) }
    }).catch(() => setReady(true))
  }

  useEffect(() => { checkLogin() }, [])

  const login = async (username, password) => {
    const res = await post('/api/login', { username, password })
    if (!res.ok) throw new Error('Login failed')
    const data = await res.json()
    localStorage.setItem('token', data.token)
    setUser({ ...data.user, isAdmin: data.user.is_admin })
    setMustReset(data.must_reset_password)
  }

  const logout = () => { localStorage.removeItem('token'); setUser(null); setMustReset(false) }

  const changePassword = async (oldPass, newPass) => {
    const res = await post('/api/change-password', { old_password: oldPass, new_password: newPass })
    if (!res.ok) throw new Error('Failed')
    logout()
  }

  if (!ready) {
    return <div className="flex h-screen items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div>
        <p className="mt-4 text-gray-600">Loading...</p>
      </div>
    </div>
  }

  return (
    <AuthContext.Provider value={{user, mustReset, ready, login, logout, changePassword}}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)
export default AuthContext