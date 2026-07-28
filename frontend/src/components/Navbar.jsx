import React, { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { path: '/', label: 'Dashboard', icon: '📊' },
  { path: '/interfaces', label: 'Interfaces', icon: '🔌' },
  { path: '/ips', label: 'IP Addresses', icon: '🌐' },
  { path: '/services', label: 'Services', icon: '🔧' },
  { path: '/changelog', label: 'Change Log', icon: '📝' },
]

const adminItems = [
  { path: '/admin/users', label: 'Users', icon: '👥' },
  { path: '/admin/devices', label: 'SNMP Devices', icon: '📡' },
]

export default function Navbar() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const [dropdownOpen, setDropdownOpen] = useState(false)

  return (
    <nav className="navbar" role="navigation" aria-label="Main navigation">
      <div className="flex items-center gap-4">
        <h1 className="navbar-title">NetFlow Monitor</h1>
        <div className="hidden md:flex md:gap-1">
          {navItems.map(item => (
            <Link
              key={item.path}
              to={item.path}
              className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                location.pathname === item.path
                  ? 'bg-white/20 text-white'
                  : 'text-blue-100 hover:bg-white/10'
              }`}
              aria-current={location.pathname === item.path ? 'page' : undefined}
            >
              <span className="flex items-center gap-2">
                {item.icon} {item.label}
              </span>
            </Link>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-3">
        {user?.is_admin && (
          <div className="hidden md:flex md:gap-1">
            {adminItems.map(item => (
              <Link
                key={item.path}
                to={item.path}
                className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  location.pathname === item.path
                    ? 'bg-white/20 text-white'
                    : 'text-blue-100 hover:bg-white/10'
                }`}
              >
                <span className="flex items-center gap-2">
                  {item.icon} {item.label}
                </span>
              </Link>
            ))}
          </div>
        )}

        <div className="dropdown" onClick={e => e.stopPropagation()}>
          <button
            className="flex items-center gap-2 px-3 py-2 rounded-md text-sm bg-white/10 hover:bg-white/20 transition-colors"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            aria-expanded={dropdownOpen}
            aria-haspopup="true"
          >
            <span className="w-8 h-8 rounded-full bg-blue-400 flex items-center justify-center font-semibold">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </span>
            <span className="hidden sm:block">{user?.username}</span>
          </button>
          
          {dropdownOpen && (
            <div className="dropdown-menu" role="menu">
              <button className="dropdown-item" role="menuitem" onClick={() => setDropdownOpen(false)}>
                Profile
              </button>
              {user?.is_admin && (
                <>
                  <hr className="dropdown-divider" />
                  <button className="dropdown-item" role="menuitem" onClick={() => { setDropdownOpen(false); window.location.href = '/admin/users'; }}>
                    User Management
                  </button>
                  <button className="dropdown-item" role="menuitem" onClick={() => { setDropdownOpen(false); window.location.href = '/admin/devices'; }}>
                    SNMP Devices
                  </button>
                </>
              )}
              <hr className="dropdown-divider" />
              <button className="dropdown-item text-red-600" role="menuitem" onClick={logout}>
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
    </nav>
  )
}