import { Copy, Edit3, KeyRound, Plus, PowerOff, ShieldCheck } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api, formatDate, toUtc } from '../api'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Credential, CredentialScopeDefinition } from '../types'

function ScopePicker({ definitions, selected }: { definitions: CredentialScopeDefinition[]; selected: string[] }) {
  return <fieldset className="credential-scope-picker">
    <legend>API access policy</legend>
    <p className="field-help">Select only the endpoint groups this machine identity needs. At least one scope is required.</p>
    {definitions.map(definition => <label className="credential-scope-option" key={definition.scope}>
      <input type="checkbox" name="scope" value={definition.scope} defaultChecked={selected.includes(definition.scope)} />
      <span><b>{definition.name}</b><code>{definition.scope}</code><small>{definition.description}</small>{definition.endpoints.map(endpoint => <em key={endpoint}>{endpoint}</em>)}</span>
    </label>)}
  </fieldset>
}

export default function Credentials({ embedded = false }: { embedded?: boolean }) {
  const [items, setItems] = useState<Credential[]>([])
  const [scopeDefinitions, setScopeDefinitions] = useState<CredentialScopeDefinition[]>([])
  const [createOpen, setCreateOpen] = useState(false)
  const [created, setCreated] = useState<Credential | null>(null)
  const [editingScopes, setEditingScopes] = useState<Credential | null>(null)
  const [revoking, setRevoking] = useState<Credential | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  const load = async () => {
    try {
      const [credentials, definitions] = await Promise.all([
        api<Credential[]>('/api/v1/admin/api-credentials'),
        api<CredentialScopeDefinition[]>('/api/v1/admin/api-credential-scopes'),
      ])
      setItems(credentials); setScopeDefinitions(definitions)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load API credentials') }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const selectedScopes = (form: FormData) => form.getAll('scope').map(String)
  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const scopes = selectedScopes(form)
    if (!scopes.length) { setError('Select at least one API scope.'); return }
    const expiry = String(form.get('expires_at') || '')
    try {
      const result = await api<Credential>('/api/v1/admin/api-credentials', {
        method: 'POST',
        body: JSON.stringify({ name: form.get('name'), expires_at: expiry ? toUtc(expiry) : null, scopes }),
      })
      setCreateOpen(false); setCreated(result); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not create credential') }
  }
  const updateScopes = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!editingScopes) return; setError('')
    const scopes = selectedScopes(new FormData(event.currentTarget))
    if (!scopes.length) { setError('Select at least one API scope.'); return }
    try {
      await api(`/api/v1/admin/api-credentials/${editingScopes.id}/scopes`, {
        method: 'PUT', body: JSON.stringify({ scopes }),
      })
      setEditingScopes(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not update access policy') }
  }
  const revoke = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!revoking) return
    const reason = new FormData(event.currentTarget).get('reason')
    try {
      await api(`/api/v1/admin/api-credentials/${revoking.id}/revoke`, {
        method: 'POST', body: JSON.stringify({ reason }),
      })
      setRevoking(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not revoke credential') }
  }

  if (loading) return <Spinner />
  const heading = <div><span className="eyebrow">MACHINE IDENTITY / LEAST PRIVILEGE</span><h2>API Credentials</h2><p>Administrators define the exact endpoint groups each revocable machine key may call.</p></div>
  return <>
    {!embedded && <PageHeader eyebrow="MACHINE IDENTITY / LEAST PRIVILEGE" title="API Credentials" description="Create revocable machine identities with explicit endpoint scopes." action={<button className="button button-primary" onClick={() => { setError(''); setCreateOpen(true) }}><Plus size={17} /> NEW API KEY</button>} />}
    {embedded && <div className="section-toolbar">{heading}<button className="button button-primary" onClick={() => { setError(''); setCreateOpen(true) }}><Plus size={17} /> NEW API KEY</button></div>}
    <Alert message={error} />
    <section className="panel">{items.length ? <div className="credential-grid">{items.map(item => <article className={`credential-card ${!item.active ? 'credential-disabled' : ''}`} key={item.id}><div className="credential-head"><div className="entity-icon"><KeyRound /></div><Badge tone={item.active ? 'active' : 'revoked'}>{item.active ? 'ACTIVE' : 'REVOKED'}</Badge></div><h2>{item.name}</h2><code>{item.prefix}••••••••••••</code><dl><div><dt>Access policy</dt><dd>{item.scopes.join(', ')}</dd></div><div><dt>Created</dt><dd>{formatDate(item.created_at)}</dd></div><div><dt>Last used</dt><dd>{formatDate(item.last_used_at)}</dd></div><div><dt>Expires</dt><dd>{formatDate(item.expires_at)}</dd></div></dl>{item.active && <div className="row-actions"><button className="table-action" onClick={() => { setError(''); setEditingScopes(item) }}><Edit3 size={15} /> Edit access</button><button className="table-action danger-action" onClick={() => { setError(''); setRevoking(item) }}><PowerOff size={15} /> Revoke</button></div>}</article>)}</div> : <Empty title="No API credentials" detail="Create a scoped credential before integrating a pipeline." />}</section>

    {createOpen && <Modal title="Create API Credential" onClose={() => setCreateOpen(false)}><Alert message={error} /><form className="form-stack" onSubmit={create}><label>Credential name<input name="name" required minLength={2} maxLength={120} placeholder="jenkins-production" /></label><label>Expiration (optional)<input name="expires_at" type="datetime-local" /></label><ScopePicker definitions={scopeDefinitions} selected={['policy:read']} /><div className="info-note"><ShieldCheck size={15} /> The raw key is displayed once. Scope changes take effect immediately without rotating the credential.</div><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setCreateOpen(false)}>Cancel</button><button className="button button-primary">Generate key</button></div></form></Modal>}
    {editingScopes && <Modal title={`Access Policy / ${editingScopes.name}`} onClose={() => setEditingScopes(null)}><Alert message={error} /><form className="form-stack" onSubmit={updateScopes}><ScopePicker definitions={scopeDefinitions} selected={editingScopes.scopes} /><div className="info-note"><ShieldCheck size={15} /> Replacing scopes is immediate and audited. Revoked credentials remain immutable.</div><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditingScopes(null)}>Cancel</button><button className="button button-primary">Save access policy</button></div></form></Modal>}
    {created && <Modal title="API Key Created" onClose={() => { setCreated(null); void load() }}><div className="one-time"><KeyRound /><h3>Copy this key now</h3><p>It will never be shown again. Only its cryptographic hash is stored.</p><div className="secret-value"><code>{created.api_key}</code><button onClick={() => navigator.clipboard.writeText(created.api_key || '')} aria-label="Copy API key"><Copy size={17} /></button></div><p>Access policy: <code>{created.scopes.join(', ')}</code></p><button className="button button-primary" onClick={() => setCreated(null)}>I have stored the key</button></div></Modal>}
    {revoking && <Modal title="Revoke API Credential" onClose={() => setRevoking(null)}><Alert message={error} /><form className="form-stack" onSubmit={revoke}><p>Pipeline calls using <b>{revoking.name}</b> will immediately fail authentication.</p><label>Reason<textarea name="reason" required minLength={5} maxLength={2000} rows={3} /></label><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setRevoking(null)}>Cancel</button><button className="button button-danger">Revoke key</button></div></form></Modal>}
  </>
}
