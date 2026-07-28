import { createContext, useContext, useState, useEffect } from 'react'
import { get, post, del } from '../api'

const AuthContext = createContext()

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null)
  const [mustReset, setMustReset] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (token) {
      get('/api/me').then(res => {
        if (res.ok) {
          res.json().then(data => {
            setUser({ ...data, isAdmin: data.is_admin })
            setLoading(false)
          })
        } else {
          setLoading(false)
        }
      }).catch(() => setLoading(false))
    } else {
      setLoading(false)
    }
  }, [])

  const login = async (username, password) => {
    setLoading(true)
    try {
      const res = await post('/api/login', { username, password })
      if (!res.ok) throw new Error('Login failed')
      const data = await res.json()
      localStorage.setItem('token', data.token)
      setUser({ ...data.user, isAdmin: data.user.is_admin })
      setMustReset(data.must_reset_password)
    } catch (err) {
      throw err
    } finally {
      setLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
    setUser(null)
    setMustReset(false)
  }

  const changePassword = async (oldPass, newPass) => {
    const res = await post('/api/change-password', { old_password: oldPass, new_password: newPass })
    if (!res.ok) throw new Error('Failed to change password')
    // Force logout and relogin with new password
    await logout()
    await login(user.username, newPass)
  }

  const resetPassword = async () => {
    setMustReset(false)
  }

  if (loading) {
    return <div className="flex h-screen items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="inline-block animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div>
        <p className="mt-4 text-gray-600">Loading...</p>
      </div>
    </div>
  }

  return (
    <AuthContext.Provider value={{user,mustReset,loading,login,logout,changePassword,resetPassword}}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = () => useContext(AuthContext)