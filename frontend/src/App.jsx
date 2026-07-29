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
import TopSources from './pages/TopSources'
import Navbar from './components/Navbar'
import ErrorBoundary from './components/ErrorBoundary'
import './index.css'

function PrivateRoute({ children, adminOnly = false }) {
  const { user, ready } = useAuth()
  if (!ready) return <div className="flex h-screen items-center justify-center"><div className="animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div></div>
  if (!user) return <Navigate to="/login" replace />
  if (adminOnly && !user.is_admin) return <Navigate to="/" replace />
  return <>{children}</>
}

function PublicRoute({ children }) {
  const { user, ready } = useAuth()
  if (!ready) return <div className="flex h-screen items-center justify-center"><div className="animate-spin rounded-full border-4 border-t-blue-600 w-12 h-12"></div></div>
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
        <Route path="/interfaces" element={<ErrorBoundary><Interfaces /></ErrorBoundary>} />
        <Route path="/ips" element={<ErrorBoundary><IPs /></ErrorBoundary>} />
        <Route path="/services" element={<ErrorBoundary><Services /></ErrorBoundary>} />
        <Route path="/top-sources" element={<ErrorBoundary><TopSources /></ErrorBoundary>} />
        <Route path="/changelog" element={<ErrorBoundary><ChangeLog /></ErrorBoundary>} />
        <Route path="/admin/users" element={<PrivateRoute adminOnly><ErrorBoundary><AdminUsers /></ErrorBoundary></PrivateRoute>} />
        <Route path="/admin/devices" element={<PrivateRoute adminOnly><ErrorBoundary><AdminDevices /></ErrorBoundary></PrivateRoute>} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

function AppLayout() {
  return (
    <div className="app-layout">
      <Navbar />
      <main className="main-content"><Outlet /></main>
    </div>
  )
}

export default function App() {
  return <AppRoutes />
}