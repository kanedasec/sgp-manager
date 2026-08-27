import { Edit3, Plus, Power, UserRound } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api, formatDate } from '../api'
import { useAuth } from '../auth'
import { Alert, Badge, Empty, Modal, Spinner } from '../components/ui'
import type { AccessGroup, AdminUser } from '../types'

export default function Users() {
  const { user: currentUser } = useAuth()
  const [items, setItems] = useState<AdminUser[]>([])
  const [groups, setGroups] = useState<AccessGroup[]>([])
  const [editing, setEditing] = useState<Partial<AdminUser> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const load = () => Promise.all([
    api<AdminUser[]>('/api/v1/admin/users'),
    api<AccessGroup[]>('/api/v1/admin/groups'),
  ]).then(([users, accessGroups]) => { setItems(users); setGroups(accessGroups) }).finally(() => setLoading(false))
  useEffect(() => { void load() }, [])
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const body: Record<string, unknown> = {
      display_name: form.get('display_name'), email: form.get('email'), role: form.get('role'),
      group_ids: form.getAll('group_id'),
    }
    const password = String(form.get('password') || '')
    if (password) body.password = password
    if (!editing?.id) body.username = form.get('username')
    try {
      await api(editing?.id ? `/api/v1/admin/users/${editing.id}` : '/api/v1/admin/users', {
        method: editing?.id ? 'PATCH' : 'POST', body: JSON.stringify(body),
      })
      setEditing(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save user') }
  }
  const toggle = async (item: AdminUser) => {
    setError('')
    try { await api(`/api/v1/admin/users/${item.id}`, { method: 'PATCH', body: JSON.stringify({ active: !item.active }) }); await load() }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not change user access') }
  }
  if (loading) return <Spinner />
  return <>
    <div className="section-toolbar"><div><span className="eyebrow">HUMAN ACCESS / RBAC</span><h2>Portal Users</h2><p>Administrators have global access. Standard users inherit owner-scoped roles from active groups.</p></div><button className="button button-primary" onClick={() => { setError(''); setEditing({ role: 'USER', groups: [] }) }}><Plus size={17} /> NEW USER</button></div>
    <Alert message={error} />
    <section className="panel access-panel">{items.length ? <div className="user-list">{items.map(item => <article key={item.id} className={!item.active ? 'user-disabled' : ''}><div className="user-avatar"><UserRound /></div><div className="user-identity"><h3>{item.display_name}{item.id === currentUser?.id && <span>YOU</span>}</h3><code>@{item.username}</code><p>{item.email}</p><div className="user-groups">{item.role === 'ADMIN' ? <code>GLOBAL ADMINISTRATOR</code> : item.groups.length ? item.groups.map(group => <code key={group.id}>{group.slug}</code>) : <span>NO ACCESS GROUPS</span>}</div></div><div className="user-meta"><Badge tone={item.active ? 'active' : 'revoked'}>{item.active ? 'ACTIVE' : 'INACTIVE'}</Badge><small>{item.role} · created {formatDate(item.created_at)}</small></div><div className="row-actions"><button className="table-action" onClick={() => { setError(''); setEditing(item) }}><Edit3 size={15} /> Edit</button><button className="table-action danger-action" disabled={item.id === currentUser?.id} onClick={() => void toggle(item)}><Power size={15} /> {item.active ? 'Disable' : 'Enable'}</button></div></article>)}</div> : <Empty title="No portal users" detail="Create an administrator or a group-scoped portal user." />}</section>
    {editing && <Modal title={`${editing.id ? 'Edit' : 'Create'} Portal User`} onClose={() => setEditing(null)} wide><Alert message={error} /><form className="form-stack" onSubmit={submit}><div className="form-grid">{!editing.id && <label>Username<input name="username" required minLength={2} maxLength={64} pattern="[A-Za-z0-9._-]+" autoComplete="off" placeholder="appsec.operator" /></label>}<label>Display name<input name="display_name" required minLength={2} maxLength={120} defaultValue={editing.display_name || ''} /></label><label>Email<input name="email" type="email" required maxLength={255} defaultValue={editing.email || ''} /></label><label>Account role<select name="role" defaultValue={editing.role || 'USER'} disabled={editing.id === currentUser?.id}><option value="USER">Standard user</option><option value="ADMIN">Administrator</option></select>{editing.id === currentUser?.id && <input type="hidden" name="role" value="ADMIN" />}</label><label className="full">{editing.id ? 'New password (optional)' : 'Initial password'}<input name="password" type="password" required={!editing.id} minLength={8} maxLength={256} autoComplete="new-password" /></label></div><fieldset><legend>Access groups</legend><p className="field-help">Groups are evaluated only for standard users. Permissions from all active groups are combined.</p><div className="group-picker">{groups.length ? groups.map(group => <label key={group.id} className={!group.active ? 'scope-inactive' : ''}><input type="checkbox" name="group_id" value={group.id} disabled={!group.active} defaultChecked={editing.groups?.some(current => current.id === group.id)} /><span><b>{group.name}</b><code>{group.slug}</code><small>{group.permissions.length} OWNER-SCOPED ROLES</small></span></label>) : <div className="info-note">No access groups exist yet. Create a group before configuring standard-user access.</div>}</div></fieldset><div className="info-note">Passwords are stored with Argon2. Passwords and tokens are never included in audit metadata.</div><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save user</button></div></form></Modal>}
  </>
}
