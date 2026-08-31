import { Navigate, Route, Routes } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from './auth'
import Layout from './components/Layout'
import { Spinner } from './components/ui'
import ApplicationDetail from './pages/ApplicationDetail'
import AccessManagement from './pages/AccessManagement'
import AuditLogs from './pages/Audit'
import Dashboard from './pages/Dashboard'
import Entities from './pages/Entities'
import Login from './pages/Login'
import Policies from './pages/Policies'
import GatePolicies from './pages/GatePolicies'
import ChangePassword from './pages/ChangePassword'

function Protected() {
  const { user, loading } = useAuth()
  if (loading) return <Spinner />
  if (!user) return <Navigate to="/login" replace />
  return user.must_change_password ? <Navigate to="/change-password" replace /> : <Layout />
}

function PasswordChangeOnly() {
  const { user, loading } = useAuth()
  if (loading) return <Spinner />
  if (!user) return <Navigate to="/login" replace />
  return user.must_change_password ? <ChangePassword /> : <Navigate to="/" replace />
}

function Home() {
  const { user } = useAuth()
  return user?.role === 'ADMIN' ? <Dashboard /> : <Navigate to="/policies" replace />
}

function AdminOnly({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  return user?.role === 'ADMIN' ? children : <Navigate to="/policies" replace />
}

export default function App() {
  return <Routes>
    <Route path="/login" element={<Login />} />
    <Route path="/change-password" element={<PasswordChangeOnly />} />
    <Route element={<Protected />}>
      <Route index element={<Home />} />
      <Route path="applications" element={<Entities kind="applications" />} />
      <Route path="applications/:id" element={<ApplicationDetail />} />
      <Route path="gates" element={<Entities kind="gates" />} />
      <Route path="gate-policies" element={<AdminOnly><GatePolicies /></AdminOnly>} />
      <Route path="policies" element={<Policies />} />
      <Route path="access" element={<AdminOnly><AccessManagement /></AdminOnly>} />
      <Route path="credentials" element={<Navigate to="/access?tab=credentials" replace />} />
      <Route path="audit" element={<AdminOnly><AuditLogs /></AdminOnly>} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
}
