import React from 'react'
import { Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Interfaces from './pages/Interfaces'
import IPs from './pages/IPs'
import Services from './pages/Services'
import ChangeLog from './pages/ChangeLog'
import AdminUsers from './pages/AdminUsers'
import AdminDevices from './pages/AdminDevices'
import PasswordReset from './pages/PasswordReset'
import Navbar from './components/Navbar'
import './index.css'

function PrivateRoute({ children, adminOnly = false }) {
  const { user, initialized } = useAuth()
  if (!initialized) return <div className="flex h-screen items-center justify-center"><div className="animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div></div>
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && !user.is_admin) return <Navigate to="/" replace />
  return children
}

function PublicRoute({ children }) {
  const { user, initialized } = useAuth()
  if (!initialized) return <div className="flex h-screen items-center justify-center"><div className="animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div></div>
  if (user) return <Navigate to="/" replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
      <Route path="/reset-password" element={<PrivateRoute><PasswordReset /></PrivateRoute>} />
      <Route element={<PrivateRoute><AppLayout /></PrivateRoute>}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/interfaces" element={<Interfaces />} />
        <Route path="/ips" element={<IPs />} />
        <Route path="/services" element={<Services />} />
        <Route path="/changelog" element={<ChangeLog />} />
        <Route path="/admin/users" element={<PrivateRoute adminOnly><AdminUsers /></PrivateRoute>} />
        <Route path="/admin/devices" element={<PrivateRoute adminOnly><AdminDevices /></PrivateRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function AppLayout({ children }) {
  return (
    <div className="app-layout">
      <Navbar />
      <main className="main-content">{children}</main>
    </div>
  )
}

export default function App() {
  return <AppRoutes />
}