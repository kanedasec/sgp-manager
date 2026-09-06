import { LockKeyhole, ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from '../auth'
import { Alert } from '../components/ui'

export default function Login() {
  const { user, login, verifyMfa } = useAuth()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [mfaToken, setMfaToken] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  if (user) return <Navigate to={user.must_change_password ? '/change-password' : '/'} replace />

  const submitCredentials = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError('')
    try {
      const result = await login(username, password)
      if (result.mfaRequired) setMfaToken(result.mfaToken)
    } catch (e) { setError(e instanceof Error ? e.message : 'Login failed') } finally { setBusy(false) }
  }
  const submitCode = async (event: FormEvent) => {
    event.preventDefault(); if (!mfaToken) return; setBusy(true); setError('')
    try { await verifyMfa(mfaToken, code) } catch (e) { setError(e instanceof Error ? e.message : 'Invalid code') } finally { setBusy(false) }
  }

  return <main className="login-page">
    <div className="login-grid" aria-hidden="true" />
    <section className="login-intro"><div className="login-kicker"><ShieldCheck size={18} /> CONTROL PLANE / 01</div><h1>Security Gate<br /><em>Policy Manager</em></h1><p>Centralized, explicit and auditable security gate bypass policies for CI/CD pipelines.</p><div className="login-principles"><span>01 / FAIL CLOSED</span><span>02 / TIME BOUNDED</span><span>03 / FULLY AUDITED</span></div></section>
    <section className="login-card"><div className="corner top-left" /><div className="corner bottom-right" /><LockKeyhole size={28} /><span className="eyebrow">ADMINISTRATIVE ACCESS</span>
      {!mfaToken ? <>
        <h2>Sign in</h2><p>Use your AppSec administrator credentials.</p><Alert message={error} />
        <form onSubmit={submitCredentials}><label>Username<input autoFocus autoComplete="username" required maxLength={64} value={username} onChange={e => setUsername(e.target.value)} /></label><label>Password<input type="password" autoComplete="current-password" required maxLength={256} value={password} onChange={e => setPassword(e.target.value)} /></label><button className="button button-primary" disabled={busy}>{busy ? 'AUTHENTICATING…' : 'AUTHENTICATE'}</button></form>
      </> : <>
        <h2>Verify your identity</h2><p>Enter the 6-digit code from your authenticator app.</p><Alert message={error} />
        <form onSubmit={submitCode}><label>Authentication code<input autoFocus inputMode="numeric" pattern="[0-9]*" autoComplete="one-time-code" required minLength={6} maxLength={8} value={code} onChange={e => setCode(e.target.value)} /></label><button className="button button-primary" disabled={busy}>{busy ? 'VERIFYING…' : 'VERIFY'}</button></form>
      </>}
    </section>
  </main>
}
