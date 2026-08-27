import { KeyRound, ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useAuth } from '../auth'
import { Alert } from '../components/ui'

export default function ChangePassword() {
  const { user, changePassword, logout } = useAuth()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const currentPassword = String(form.get('current_password') || '')
    const newPassword = String(form.get('new_password') || '')
    const confirmation = String(form.get('confirmation') || '')
    if (newPassword !== confirmation) { setError('The new password and confirmation do not match.'); return }
    if (newPassword === currentPassword) { setError('The new password must be different from the initial password.'); return }
    setBusy(true)
    try { await changePassword(currentPassword, newPassword) }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not change the password') }
    finally { setBusy(false) }
  }

  return <main className="password-change-page">
    <div className="login-grid" aria-hidden="true" />
    <section className="password-change-context">
      <div className="login-kicker"><ShieldCheck size={18} /> FIRST-RUN SECURITY / 01</div>
      <h1>Replace the<br /><em>bootstrap key.</em></h1>
      <p>The initial credential exists only to establish the first administrator. Administrative APIs, policies and documentation remain locked until it is replaced.</p>
      <div className="change-lock-state"><span>PORTAL ACCESS</span><b>LOCKED</b></div>
    </section>
    <section className="login-card password-change-card">
      <div className="corner top-left" /><div className="corner bottom-right" />
      <KeyRound size={29} /><span className="eyebrow">MANDATORY PASSWORD CHANGE</span>
      <h2>Secure {user?.username}</h2><p>Choose a unique password with at least 12 characters.</p>
      <Alert message={error} />
      <form onSubmit={submit}>
        <label>Current bootstrap password<input autoFocus name="current_password" type="password" autoComplete="current-password" required maxLength={256} /></label>
        <label>New password<input name="new_password" type="password" autoComplete="new-password" required minLength={12} maxLength={256} /></label>
        <label>Confirm new password<input name="confirmation" type="password" autoComplete="new-password" required minLength={12} maxLength={256} /></label>
        <div className="password-rule"><b>12+</b><span>CHARACTERS · UNIQUE · NOT THE BOOTSTRAP PASSWORD</span></div>
        <button className="button button-primary" disabled={busy}>{busy ? 'SECURING ACCOUNT…' : 'CHANGE PASSWORD & UNLOCK'}</button>
        <button type="button" className="change-signout" onClick={logout}>Sign out instead</button>
      </form>
    </section>
  </main>
}
