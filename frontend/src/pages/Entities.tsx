import { AppWindow, Edit3, Plus, Power, Search, Workflow } from 'lucide-react'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Entity, Owner } from '../types'

const severities = ['low', 'medium', 'high', 'critical']

export default function Entities({ kind }: { kind: 'applications' | 'gates' }) {
  const applicationMode = kind === 'applications'
  const [items, setItems] = useState<Entity[]>([])
  const [owners, setOwners] = useState<Owner[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<Partial<Entity> | null>(null)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { user, can } = useAuth()
  const load = () => Promise.all([
    api<Entity[]>(`/api/v1/admin/${kind}`),
    ...(!applicationMode ? [api<Owner[]>('/api/v1/admin/owner-labels')] : []),
  ]).then(([entities, ownerItems]) => { setItems(entities); if (ownerItems) setOwners(ownerItems as Owner[]) }).finally(() => setLoading(false))
  useEffect(() => { void load() }, [kind])
  const filtered = useMemo(() => items.filter(x => `${x.name} ${x.slug}`.toLowerCase().includes(query.toLowerCase())), [items, query])
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const body = {
      name: form.get('name'), slug: form.get('slug'), description: form.get('description') || null,
      ...(!applicationMode ? { owner_id: form.get('owner_id'), default_blocking_severities: severities.filter(s => form.get(`default_${s}`)) } : {}),
    }
    try {
      if (editing?.id) await api(`/api/v1/admin/${kind}/${editing.id}`, { method: 'PATCH', body: JSON.stringify(body) })
      else await api(`/api/v1/admin/${kind}`, { method: 'POST', body: JSON.stringify(body) })
      setEditing(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save') }
  }
  const toggle = async (item: Entity) => { try { await api(`/api/v1/admin/${kind}/${item.id}`, { method: 'PATCH', body: JSON.stringify({ active: !item.active }) }); await load() } catch (e) { setError(e instanceof Error ? e.message : 'Could not change state') } }
  const label = applicationMode ? 'Application' : 'Security Gate'
  const canCreate = applicationMode ? user?.role === 'ADMIN' : owners.some(owner => can('gates', 'create', owner.slug))
  const canEdit = (item: Entity) => applicationMode ? user?.role === 'ADMIN' : !!item.owner && can('gates', 'edit', item.owner.slug)
  if (loading) return <Spinner />
  return <><PageHeader eyebrow={`INVENTORY / ${applicationMode ? 'PROTECTED ASSETS' : 'ENFORCEMENT POINTS'}`} title={applicationMode ? 'Applications' : 'Security Gates'} description={applicationMode ? 'Services and products that consume security policy decisions.' : 'Owner-scoped controls and their default blocking severities.'} action={canCreate ? <button className="button button-primary" onClick={() => setEditing({})}><Plus size={17} /> NEW {label.toUpperCase()}</button> : undefined} />
    <section className="panel"><div className="toolbar"><label className="search"><Search size={17} /><input aria-label={`Search ${kind}`} placeholder={`Search ${kind}…`} value={query} onChange={e => setQuery(e.target.value)} /></label><span>{filtered.length} RECORDS</span></div>
      {filtered.length ? <div className="entity-grid">{filtered.map(item => <article className={`entity-card ${!item.active ? 'entity-disabled' : ''}`} key={item.id} onClick={() => applicationMode && navigate(`/applications/${item.id}`)}><div className="entity-icon">{applicationMode ? <AppWindow /> : <Workflow />}</div><div className="entity-title"><div><h2>{item.name}</h2><code>{item.slug}</code></div><Badge tone={item.active ? 'active' : 'revoked'}>{item.active ? 'ACTIVE' : 'INACTIVE'}</Badge></div>{item.owner && <div className="owner-stamp">OWNER / <b>{item.owner.slug}</b></div>}<p>{item.description || 'No description provided.'}</p>{!applicationMode && <div className="gate-defaults"><span>BLOCKS BY DEFAULT</span><div className="badge-row">{item.default_blocking_severities?.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div></div>}{canEdit(item) && <div className="entity-actions"><button onClick={e => { e.stopPropagation(); setEditing(item) }}><Edit3 size={15} /> Edit</button><button onClick={e => { e.stopPropagation(); void toggle(item) }}><Power size={15} /> {item.active ? 'Disable' : 'Enable'}</button></div>}</article>)}</div> : <Empty title={`No ${kind} found`} detail={`Create the first ${label.toLowerCase()} or change the search term.`} />}
    </section>
    {editing && <Modal title={`${editing.id ? 'Edit' : 'Create'} ${label}`} onClose={() => setEditing(null)}><Alert message={error} /><form className="form-stack" onSubmit={submit}><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editing.name} /></label><label>Identifier / slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editing.slug} placeholder="payment-api" /></label>{!applicationMode && <label>Owner<select name="owner_id" required defaultValue={editing.owner_id || ''}><option value="" disabled>Select owner</option>{owners.filter(owner => editing.id ? can('gates', 'edit', owner.slug) : can('gates', 'create', owner.slug)).map(owner => <option key={owner.id} value={owner.id}>{owner.name} — {owner.slug}</option>)}</select></label>}<label>Description<textarea name="description" maxLength={2000} rows={4} defaultValue={editing.description || ''} /></label>{!applicationMode && <fieldset className="severity-picker"><legend>Default blocking severities</legend>{severities.map(s => <label key={s} className={`severity-option severity-${s}`}><input type="checkbox" name={`default_${s}`} defaultChecked={editing.id ? editing.default_blocking_severities?.includes(s) : true} /><span>{s.toUpperCase()}</span></label>)}<p className="field-help">Findings at these severities block the gate unless an active application bypass explicitly removes them.</p></fieldset>}<div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save {label}</button></div></form></Modal>}
  </>
}
