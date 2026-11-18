const BASE = import.meta.env.VITE_API_BASE_URL || ''

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = sessionStorage.getItem('sgbm_token')
  const response = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...options.headers },
  })
  if (response.status === 401 && !['/api/v1/auth/login', '/api/v1/auth/mfa/verify'].includes(path)) {
    sessionStorage.removeItem('sgbm_token')
    window.dispatchEvent(new Event('sgbm-unauthorized'))
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const detail = Array.isArray(body.detail) ? body.detail.map((x: { msg?: string }) => x.msg).join('; ') : body.detail
    throw new ApiError(response.status, detail || 'Request failed')
  }
  if (response.status === 204) return undefined as T
  return response.json()
}

export async function apiDownload(path: string, fallbackName: string): Promise<void> {
  const token = sessionStorage.getItem('sgbm_token')
  const response = await fetch(`${BASE}${path}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
  if (response.status === 401) {
    sessionStorage.removeItem('sgbm_token')
    window.dispatchEvent(new Event('sgbm-unauthorized'))
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new ApiError(response.status, typeof body.detail === 'string' ? body.detail : 'Download failed')
  }
  const name = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') || '')?.[1] || fallbackName
  const url = URL.createObjectURL(await response.blob())
  const link = document.createElement('a')
  link.href = url; link.download = name; link.click()
  URL.revokeObjectURL(url)
}

export const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
export const toUtc = (local: string) => new Date(local).toISOString()

