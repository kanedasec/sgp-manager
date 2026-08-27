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
  if (response.status === 401 && path !== '/api/v1/auth/login') {
    sessionStorage.removeItem('sgbm_token')
    window.dispatchEvent(new Event('sgbm-unauthorized'))
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    const detail = Array.isArray(body.detail) ? body.detail.map((x: { msg?: string }) => x.msg).join('; ') : body.detail
    throw new ApiError(response.status, detail || 'Request failed')
  }
  return response.json()
}

export const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : '—'
export const toUtc = (local: string) => new Date(local).toISOString()

