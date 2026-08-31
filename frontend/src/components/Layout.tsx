import { Activity, AppWindow, FileClock, Gauge, Layers3, LogOut, Menu, ShieldCheck, UsersRound, Workflow, X } from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth'

const nav = [
  { to: '/', label: 'Dashboard', icon: Gauge, admin: true },
  { to: '/applications', label: 'Applications', icon: AppWindow },
  { to: '/gates', label: 'Security Gates', icon: Workflow, resource: 'gates' },
  { to: '/gate-policies', label: 'Gate Policies', icon: Layers3, admin: true },
  { to: '/policies', label: 'Bypass Policies', icon: ShieldCheck, resource: 'policies' },
  { to: '/access', label: 'Access Management', icon: UsersRound, admin: true },
  { to: '/audit', label: 'Audit Logs', icon: FileClock, admin: true },
]

export default function Layout() {
  const { user, logout } = useAuth()
  const [open, setOpen] = useState(false)
  const visibleNav = nav.filter(item => !item.admin || user?.role === 'ADMIN').filter(item =>
    !item.resource || user?.role === 'ADMIN' || user?.permissions.some(permission => permission.includes(`-${item.resource}:`))
  )
  return <div className="shell">
    <a className="skip-link" href="#main">Skip to content</a>
    <aside className={`sidebar ${open ? 'sidebar-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><ShieldCheck /></div><div><strong>SECURITY GATE</strong><span>Policy Manager</span></div></div>
      <button className="mobile-close" onClick={() => setOpen(false)} aria-label="Close menu"><X /></button>
      <div className="system-status"><Activity size={15} /><span>POLICY ENGINE</span><b>ONLINE</b></div>
      <nav aria-label="Main navigation">{visibleNav.map(({ to, label, icon: Icon }, index) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setOpen(false)}><span className="nav-index">0{index + 1}</span><Icon size={18} /><span>{label}</span></NavLink>)}</nav>
      <div className="sidebar-user"><div className="avatar">{user?.display_name.slice(0, 2).toUpperCase()}</div><div><strong>{user?.display_name}</strong><span>{user?.role}</span></div><button onClick={logout} aria-label="Sign out"><LogOut size={17} /></button></div>
    </aside>
    <div className="workspace">
      <header className="mobile-bar"><button onClick={() => setOpen(true)} aria-label="Open menu"><Menu /></button><strong>SG / BYPASS</strong></header>
      <main id="main"><Outlet /></main>
      <footer><span>SECURITY GATE BYPASS MANAGER</span><span>UTC POLICY ENGINE · FAIL CLOSED</span></footer>
    </div>
  </div>
}
