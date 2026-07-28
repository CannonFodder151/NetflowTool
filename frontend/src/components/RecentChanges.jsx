import React from 'react'

export default function RecentChanges({ data }) {
  if (!data || data.length === 0) return <p className="text-gray text-center py-4">No recent events</p>

  return (
    <div className="overflow-x-auto">
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Device</th>
            <th>Action</th>
            <th>Message</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {data.map((c, i) => (
            <tr key={i}>
              <td className="text-sm">{c.ts || c.timestamp}</td>
              <td>{c.device || c.device_name}</td>
              <td>{c.action}</td>
              <td className="max-w-xs truncate">{c.message}</td>
              <td>
                <span className={`badge ${c.risk === 'critical' || c.risk_level === 'critical' ? 'badge-red' : c.risk === 'high' || c.risk_level === 'high' ? 'badge-red' : 'badge-yellow'}`}>
                  {c.risk || c.risk_level}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}