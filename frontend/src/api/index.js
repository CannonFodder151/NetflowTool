const BASE = ''

function headers() {
  const h = { 'Content-Type': 'application/json' }
  const t = localStorage.getItem('token')
  if (t) h['Authorization'] = `Bearer ${t}`
  return h
}

export async function get(url) {
  return fetch(BASE + url, { headers: headers() })
}

export async function post(url, body) {
  return fetch(BASE + url, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify(body)
  })
}

export async function put(url, body) {
  return fetch(BASE + url, {
    method: 'PUT',
    headers: headers(),
    body: JSON.stringify(body)
  })
}

export async function del(url) {
  return fetch(BASE + url, {
    method: 'DELETE',
    headers: headers()
  })
}

export function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export function timeAgo(ts) {
  if (!ts) return ''
  const diff = Math.floor((Date.now() - new Date(ts)) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}