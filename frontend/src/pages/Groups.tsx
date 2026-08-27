import { Edit3, Plus, Power, UsersRound } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api } from '../api'
import { Alert, Badge, Empty, Modal, Spinner } from '../components/ui'
import type { AccessGroup, Owner } from '../types'

const actions = ['view', 'create', 'edit'] as const
const resources = ['gates', 'policies'] as const

export default function Groups() {
  const [groups, setGroups] = useState<AccessGroup[]>([])
  const [owners, setOwners] = useState<Owner[]>([])
  const [editing, setEditing] = useState<Partial<AccessGroup> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const load = () => Promise.all([api<AccessGroup[]>('/api/v1/admin/groups'), api<Owner[]>('/api/v1/admin/owners')]).then(([g, o]) => { setGroups(g); setOwners(o) }).finally(() => setLoading(false))
  useEffect(() => { void load() }, [])
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const body = { name: form.get('name'), slug: form.get('slug'), description: form.get('description') || null, permissions: form.getAll('permission') }
    try {
      await api(editing?.id ? `/api/v1/admin/groups/${editing.id}` : '/api/v1/admin/groups', {
        method: editing?.id ? 'PATCH' : 'POST', body: JSON.stringify(body),
      })
      setEditing(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save group') }
  }
  const toggle = async (group: AccessGroup) => {
    try { await api(`/api/v1/admin/groups/${group.id}`, { method: 'PATCH', body: JSON.stringify({ active: !group.active }) }); await load() }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not change group state') }
  }
  if (loading) return <Spinner />
  const scopes = [{ id: 'all', name: 'All owners', slug: 'all', active: true }, ...owners]
  return <>
    <div className="section-toolbar"><div><span className="eyebrow">RBAC / OWNER-SCOPED ROLES</span><h2>Access Groups</h2><p>Bundle view, create and edit roles, then assign users to the group.</p></div><button className="button button-primary" onClick={() => { setError(''); setEditing({ permissions: [] }) }}><Plus size={17} /> NEW GROUP</button></div>
    <Alert message={error} />
    <section className="panel access-panel">{groups.length ? <div className="group-list">{groups.map(group => <article key={group.id} className={!group.active ? 'user-disabled' : ''}><div className="group-head"><div className="entity-icon"><UsersRound /></div><div><h3>{group.name}</h3><code>{group.slug}</code></div><Badge tone={group.active ? 'active' : 'revoked'}>{group.active ? 'ACTIVE' : 'INACTIVE'}</Badge></div><p>{group.description || 'No description provided.'}</p><div className="permission-cloud">{group.permissions.length ? group.permissions.map(role => <code key={role}>{role}</code>) : <span>NO ROLES</span>}</div><div className="group-foot"><span>{group.user_count} USERS</span><div className="row-actions"><button className="table-action" onClick={() => setEditing(group)}><Edit3 size={15} /> Edit roles</button><button className="table-action danger-action" onClick={() => void toggle(group)}><Power size={15} /> {group.active ? 'Disable' : 'Enable'}</button></div></div></article>)}</div> : <Empty title="No access groups" detail="Create a group and assign owner-scoped roles." />}</section>
    {editing && <Modal title={`${editing.id ? 'Edit' : 'Create'} Access Group`} onClose={() => setEditing(null)} wide><Alert message={error} /><form className="form-stack" onSubmit={submit}><div className="form-grid"><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editing.name || ''} placeholder="AppSec Chapters" /></label><label>Slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editing.slug || ''} placeholder="appsec-chapters" /></label><label className="full">Description<textarea name="description" maxLength={2000} rows={3} defaultValue={editing.description || ''} /></label></div><fieldset><legend>Role matrix</legend><p className="field-help">Global roles use <code>:all</code>. Owner rows grant the same action only inside that boundary.</p><div className="role-matrix"><div className="role-matrix-head"><b>OWNER SCOPE</b>{resources.flatMap(resource => actions.map(action => <span key={`${resource}-${action}`}>{action}<small>{resource}</small></span>))}</div>{scopes.map(scope => <div className={`role-matrix-row ${!scope.active ? 'scope-inactive' : ''}`} key={scope.id}><div><b>{scope.name}</b><code>{scope.slug}</code></div>{resources.flatMap(resource => actions.map(action => { const role = `${action}-${resource}:${scope.slug}`; return <label key={role} title={role}><input type="checkbox" name="permission" value={role} defaultChecked={editing.permissions?.includes(role)} /><span>{action.slice(0, 1).toUpperCase()}</span></label> }))}</div>)}</div></fieldset><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save group and roles</button></div></form></Modal>}
  </>
}
