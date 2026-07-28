import React from 'react'

export default function Tile({ title, span = 4, children, actions }) {
  return (
    <div className="tile" style={{ gridColumn: `span ${span}` }}>
      <div className="tile-header">
        <h3 className="tile-title">{title}</h3>
        {actions && <div className="flex gap-2">{actions}</div>}
      </div>
      <div className="tile-content">
        {children}
      </div>
    </div>
  )
}