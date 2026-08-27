import { Copy, KeyRound, Plus, PowerOff } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api, formatDate, toUtc } from '../api'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Credential } from '../types'

export default function Credentials({ embedded = false }: { embedded?: boolean }) {
  const [items, setItems] = useState<Credential[]>([])
  const [createOpen, setCreateOpen] = useState(false)
  const [created, setCreated] = useState<Credential | null>(null)
  const [revoking, setRevoking] = useState<Credential | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const load = () => api<Credential[]>('/api/v1/admin/api-credentials').then(setItems).finally(() => setLoading(false))
  useEffect(() => { void load() }, [])
  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError(''); const form = new FormData(event.currentTarget); const expiry = String(form.get('expires_at') || '')
    try { const result = await api<Credential>('/api/v1/admin/api-credentials', { method: 'POST', body: JSON.stringify({ name: form.get('name'), expires_at: expiry ? toUtc(expiry) : null }) }); setCreateOpen(false); setCreated(result); load() } catch (e) { setError(e instanceof Error ? e.message : 'Could not create credential') }
  }
  const revoke = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!revoking) return; const reason = new FormData(event.currentTarget).get('reason')
    try { await api(`/api/v1/admin/api-credentials/${revoking.id}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) }); setRevoking(null); load() } catch (e) { setError(e instanceof Error ? e.message : 'Could not revoke credential') }
  }
  if (loading) return <Spinner />
  return <>{!embedded && <PageHeader eyebrow="MACHINE IDENTITY / POLICY:READ" title="API Credentials" description="Hashed, revocable credentials for CI/CD policy evaluation." action={<button className="button button-primary" onClick={() => { setError(''); setCreateOpen(true) }}><Plus size={17} /> NEW API KEY</button>} />}
    {embedded && <div className="section-toolbar"><div><span className="eyebrow">MACHINE IDENTITY / POLICY:READ</span><h2>API Credentials</h2><p>Hashed, revocable credentials for CI/CD policy evaluation.</p></div><button className="button button-primary" onClick={() => { setError(''); setCreateOpen(true) }}><Plus size={17} /> NEW API KEY</button></div>}
    <section className="panel">{items.length ? <div className="credential-grid">{items.map(item => <article className={`credential-card ${!item.active ? 'credential-disabled' : ''}`} key={item.id}><div className="credential-head"><div className="entity-icon"><KeyRound /></div><Badge tone={item.active ? 'active' : 'revoked'}>{item.active ? 'ACTIVE' : 'REVOKED'}</Badge></div><h2>{item.name}</h2><code>{item.prefix}••••••••••••</code><dl><div><dt>Scope</dt><dd>{item.scopes.join(', ')}</dd></div><div><dt>Created</dt><dd>{formatDate(item.created_at)}</dd></div><div><dt>Last used</dt><dd>{formatDate(item.last_used_at)}</dd></div><div><dt>Expires</dt><dd>{formatDate(item.expires_at)}</dd></div></dl>{item.active && <button className="button button-quiet-danger" onClick={() => { setError(''); setRevoking(item) }}><PowerOff size={15} /> Revoke credential</button>}</article>)}</div> : <Empty title="No API credentials" detail="Create a scoped credential before integrating a pipeline." />}</section>
    {createOpen && <Modal title="Create API Credential" onClose={() => setCreateOpen(false)}><Alert message={error} /><form className="form-stack" onSubmit={create}><label>Credential name<input name="name" required minLength={2} maxLength={120} placeholder="jenkins-production" /></label><label>Expiration (optional)<input name="expires_at" type="datetime-local" /></label><div className="info-note">The key receives <code>policy:read</code>. Application-level scopes can be added later without changing the credential model.</div><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setCreateOpen(false)}>Cancel</button><button className="button button-primary">Generate key</button></div></form></Modal>}
    {created && <Modal title="API Key Created" onClose={() => { setCreated(null); load() }}><div className="one-time"><KeyRound /><h3>Copy this key now</h3><p>It will never be shown again. Only its cryptographic hash is stored.</p><div className="secret-value"><code>{created.api_key}</code><button onClick={() => navigator.clipboard.writeText(created.api_key || '')} aria-label="Copy API key"><Copy size={17} /></button></div><button className="button button-primary" onClick={() => setCreated(null)}>I have stored the key</button></div></Modal>}
    {revoking && <Modal title="Revoke API Credential" onClose={() => setRevoking(null)}><Alert message={error} /><form className="form-stack" onSubmit={revoke}><p>Pipeline calls using <b>{revoking.name}</b> will immediately fail authentication.</p><label>Reason<textarea name="reason" required minLength={5} maxLength={2000} rows={3} /></label><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setRevoking(null)}>Cancel</button><button className="button button-danger">Revoke key</button></div></form></Modal>}
  </>
}
