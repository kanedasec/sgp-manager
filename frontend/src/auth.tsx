import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { api } from './api'

export type SessionUser = { id: string; username: string; display_name: string; email: string; role: string; groups: string[]; permissions: string[]; must_change_password: boolean }
type AuthValue = {
  user: SessionUser | null; loading: boolean; login: (username: string, password: string) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  logout: () => void; can: (resource: 'gates' | 'policies', action: 'view' | 'create' | 'edit', ownerSlug?: string) => boolean
}
const AuthContext = createContext<AuthValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<SessionUser | null>(null)
  const [loading, setLoading] = useState(true)
  const logout = () => {
    void fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => undefined)
    sessionStorage.removeItem('sgbm_token')
    setUser(null)
  }

  useEffect(() => {
    const token = sessionStorage.getItem('sgbm_token')
    if (!token) { setLoading(false); return }
    api<SessionUser>('/api/v1/auth/me').then(setUser).catch(logout).finally(() => setLoading(false))
    window.addEventListener('sgbm-unauthorized', logout)
    return () => window.removeEventListener('sgbm-unauthorized', logout)
  }, [])

  const login = async (username: string, password: string) => {
    const result = await api<{ access_token: string; user: SessionUser }>('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })
    sessionStorage.setItem('sgbm_token', result.access_token)
    setUser(result.user)
  }
  const changePassword = async (currentPassword: string, newPassword: string) => {
    const result = await api<{ access_token: string; user: SessionUser }>('/api/v1/auth/change-password', {
      method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    })
    sessionStorage.setItem('sgbm_token', result.access_token)
    setUser(result.user)
  }
  const can: AuthValue['can'] = (resource, action, ownerSlug) => {
    if (user?.role === 'ADMIN') return true
    if (!user) return false
    return user.permissions.includes(`${action}-${resource}:all`) || (!!ownerSlug && user.permissions.includes(`${action}-${resource}:${ownerSlug}`))
  }
  return <AuthContext.Provider value={{ user, loading, login, changePassword, logout, can }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const value = useContext(AuthContext)
  if (!value) throw new Error('AuthProvider is missing')
  return value
}
