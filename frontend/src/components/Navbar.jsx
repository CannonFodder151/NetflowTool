import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { path: '/', label: 'Dashboard' },
  { path: '/interfaces', label: 'Interfaces' },
  { path: '/ips', label: 'IPs' },
  { path: '/services', label: 'Services' },
  { path: '/changelog', label: 'Change Log' },
]

const adminItems = [
  { path: '/admin/users', label: 'Users' },
  { path: '/admin/devices', label: 'SNMP Devices' },
]

export default function Navbar() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const closeMenu = () => setMenuOpen(false)
    window.addEventListener('click', closeMenu)
    return () => window.removeEventListener('click', closeMenu)
  }, [])

  const isActive = (path) => location.pathname === path ? 'navbar-link active' : 'navbar-link'

  return (
    <nav className="navbar">
      <div style={{display:'flex',alignItems:'center',gap:'1.5rem'}}>
        <h1 className="navbar-title">NetFlow Monitor</h1>
        <div className="navbar-links">
          {navItems.map(item => (
            <Link key={item.path} to={item.path} className={isActive(item.path)}>
              {item.label}
            </Link>
          ))}
        </div>
      </div>

      <div style={{display:'flex',alignItems:'center',gap:'1rem'}}>
        {user?.is_admin && (
          <div className="navbar-links">
            {adminItems.map(item => (
              <Link key={item.path} to={item.path} className={isActive(item.path)}>
                {item.label}
              </Link>
            ))}
          </div>
        )}

        <div className="dropdown">
          <button 
            className="btn btn-sm"
            style={{background:'rgba(255,255,255,0.15)',color:'white'}}
            onClick={e => { e.stopPropagation(); setMenuOpen(!menuOpen) }}
          >
            {user?.username || 'User'}
          </button>
          {menuOpen && (
            <div className="dropdown-menu">
              <button className="dropdown-item" onClick={() => setMenuOpen(false)}>
                Signed in as: <strong>{user?.username}</strong>
              </button>
              {user?.is_admin && (
                <>
                  <hr className="dropdown-divider" />
                  <Link to="/admin/users" className="dropdown-item" style={{textDecoration:'none'}} onClick={() => setMenuOpen(false)}>
                    User Management
                  </Link>
                  <Link to="/admin/devices" className="dropdown-item" style={{textDecoration:'none'}} onClick={() => setMenuOpen(false)}>
                    SNMP Devices
                  </Link>
                </>
              )}
              <hr className="dropdown-divider" />
              <button className="dropdown-item text-red-600" onClick={logout}>
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  )
}