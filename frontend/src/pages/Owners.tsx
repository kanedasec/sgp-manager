import { Edit3, Plus, Power, Tags } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api'
import { Alert, Badge, Empty, Modal, Spinner } from '../components/ui'
import type { Owner } from '../types'

export default function Owners() {
  const [items, setItems] = useState<Owner[]>([])
  const [editing, setEditing] = useState<Partial<Owner> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const load = () => api<Owner[]>('/api/v1/admin/owners').then(setItems).finally(() => setLoading(false))
  useEffect(() => { void load() }, [])
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const body = { name: form.get('name'), slug: form.get('slug'), description: form.get('description') || null }
    try {
      await api(editing?.id ? `/api/v1/admin/owners/${editing.id}` : '/api/v1/admin/owners', {
        method: editing?.id ? 'PATCH' : 'POST', body: JSON.stringify(body),
      })
      setEditing(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save owner') }
  }
  const toggle = async (owner: Owner) => {
    try { await api(`/api/v1/admin/owners/${owner.id}`, { method: 'PATCH', body: JSON.stringify({ active: !owner.active }) }); await load() }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not change owner state') }
  }
  if (loading) return <Spinner />
  return <>
    <div className="section-toolbar"><div><span className="eyebrow">AUTHORIZATION SCOPE / LABELS</span><h2>Owners</h2><p>Reusable ownership boundaries for gates, policies and group roles.</p></div><button className="button button-primary" onClick={() => { setError(''); setEditing({}) }}><Plus size={17} /> NEW OWNER</button></div>
    <Alert message={error} />
    <section className="panel access-panel">{items.length ? <div className="owner-grid">{items.map(owner => <article key={owner.id} className={!owner.active ? 'entity-disabled' : ''}><div className="credential-head"><div className="entity-icon"><Tags /></div><Badge tone={owner.active ? 'active' : 'revoked'}>{owner.active ? 'ACTIVE' : 'INACTIVE'}</Badge></div><h3>{owner.name}</h3><code>{owner.slug}</code><p>{owner.description || 'No description provided.'}</p><div className="row-actions"><button className="table-action" onClick={() => setEditing(owner)}><Edit3 size={15} /> Edit</button><button className="table-action danger-action" onClick={() => void toggle(owner)}><Power size={15} /> {owner.active ? 'Disable' : 'Enable'}</button></div></article>)}</div> : <Empty title="No owner labels" detail="Create AppSec, Architecture, Quality or another authorization boundary." />}</section>
    {editing && <Modal title={`${editing.id ? 'Edit' : 'Create'} Owner`} onClose={() => setEditing(null)}><Alert message={error} /><form className="form-stack" onSubmit={submit}><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editing.name || ''} placeholder="Application Security" /></label><label>Slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editing.slug || ''} placeholder="appsec" /></label><label>Description<textarea name="description" maxLength={2000} rows={4} defaultValue={editing.description || ''} /></label><div className="info-note"><code>all</code> is reserved for global group roles and cannot be used as an owner slug.</div><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save owner</button></div></form></Modal>}
  </>
}
