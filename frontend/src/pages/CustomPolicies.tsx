import { Braces, Edit3, Eye, Plus, Power } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { api, formatDate } from '../api'
import { useAuth } from '../auth'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { CustomPolicy, Owner } from '../types'

type Editor = Partial<CustomPolicy> & { format: 'json' | 'yaml' }

const starterDocument = (format: 'json' | 'yaml') => format === 'json'
  ? '{\n  "rules": {\n    "require_review": true\n  }\n}'
  : 'rules:\n  require_review: true\n'

export default function CustomPolicies() {
  const [policies, setPolicies] = useState<CustomPolicy[]>([])
  const [owners, setOwners] = useState<Owner[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [selected, setSelected] = useState<CustomPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const { can } = useAuth()

  const load = async () => {
    setLoading(true)
    try {
      const [policyItems, ownerItems] = await Promise.all([
        api<CustomPolicy[]>('/api/v1/admin/custom-policies'),
        api<Owner[]>('/api/v1/admin/owner-labels'),
      ])
      setPolicies(policyItems); setOwners(ownerItems)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load custom policies') }
    finally { setLoading(false) }
  }
  useEffect(() => { void load() }, [])

  const creatableOwners = owners.filter(owner => owner.active && can('custom-policies', 'create', owner.slug))
  const openCreate = () => setEditor({ format: 'json', document: starterDocument('json') })
  const openEdit = (policy: CustomPolicy) => setEditor({ ...policy })

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!editor) return
    const form = new FormData(event.currentTarget)
    const body: Record<string, unknown> = {
      name: form.get('name'), slug: form.get('slug'), description: form.get('description') || null,
      format: editor.format, document: form.get('document'),
    }
    if (!editor.id) body.owner_id = form.get('owner_id')
    setError(''); setSaving(true)
    try {
      await api(editor.id ? `/api/v1/admin/custom-policies/${editor.id}` : '/api/v1/admin/custom-policies', {
        method: editor.id ? 'PATCH' : 'POST', body: JSON.stringify(body),
      })
      setEditor(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save custom policy') }
    finally { setSaving(false) }
  }

  const toggle = async (policy: CustomPolicy) => {
    setError('')
    try {
      await api(`/api/v1/admin/custom-policies/${policy.id}`, {
        method: 'PATCH', body: JSON.stringify({ active: !policy.active }),
      })
      await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not change custom policy state') }
  }

  if (loading) return <Spinner />
  return <>
    <PageHeader eyebrow="POLICY DOCUMENTS / OWNER SCOPED" title="Custom Policies" description="Author validated JSON or YAML policy documents without changing gate-policy enforcement." action={creatableOwners.length ? <button className="button button-primary" onClick={openCreate}><Plus size={17} /> NEW CUSTOM POLICY</button> : undefined} />
    <Alert message={error} />
    <section className="policy-principle"><Braces /><div><span>SEPARATE POLICY DOMAIN</span><b>Custom documents never alter pipeline enforcement implicitly</b><p>Gate policies remain the authoritative scanner and severity standard. Custom policies are validated, owner-scoped documents for explicitly integrated consumers.</p></div></section>
    <section className="panel">
      {policies.length ? <div className="table-wrap"><table><thead><tr><th>Policy / Owner</th><th>Format</th><th>Updated</th><th>Status</th><th /></tr></thead><tbody>{policies.map(policy => <tr key={policy.id}><td><b>{policy.name}</b><small>{policy.slug}</small><span className="owner-inline">OWNER / {policy.owner.slug}</span></td><td><Badge tone="neutral">{policy.format.toUpperCase()}</Badge></td><td>{formatDate(policy.updated_at)}</td><td><Badge tone={policy.active ? 'active' : 'revoked'}>{policy.active ? 'ACTIVE' : 'INACTIVE'}</Badge></td><td><div className="row-actions"><button className="table-action" onClick={() => setSelected(policy)}><Eye size={15} /> View</button>{can('custom-policies', 'edit', policy.owner.slug) && <><button className="table-action" onClick={() => openEdit(policy)}><Edit3 size={15} /> Edit</button><button className="table-action danger-action" onClick={() => void toggle(policy)}><Power size={15} /> {policy.active ? 'Deactivate' : 'Activate'}</button></>}</div></td></tr>)}</tbody></table></div> : <Empty title="No custom policies" detail="Create an owner-scoped JSON or YAML policy document." />}
    </section>

    {editor && <Modal wide title={`${editor.id ? 'Edit' : 'Create'} custom policy`} onClose={() => setEditor(null)}><Alert message={error} /><form className="form-stack" onSubmit={submit}><div className="form-grid"><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editor.name || ''} /></label><label>Identifier / slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editor.slug || ''} /></label>{editor.id ? <label>Owner<input value={editor.owner?.name || ''} disabled /></label> : <label>Owner<select name="owner_id" required defaultValue=""><option value="" disabled>Select owner</option>{creatableOwners.map(owner => <option key={owner.id} value={owner.id}>{owner.name} — {owner.slug}</option>)}</select></label>}<label>Document format<select value={editor.format} onChange={event => { const format = event.target.value as 'json' | 'yaml'; setEditor(current => current ? { ...current, format, document: current.id ? current.document : starterDocument(format) } : current) }}><option value="json">JSON</option><option value="yaml">YAML</option></select></label><label className="full">Description<textarea name="description" rows={3} maxLength={2000} defaultValue={editor.description || ''} /></label><label className="full">Policy document<textarea className="policy-document-editor" name="document" required minLength={2} maxLength={65536} rows={18} defaultValue={editor.document || starterDocument(editor.format)} spellCheck={false} /></label></div><p className="pipeline-note">Documents must have an object at the root and are limited to 64 KiB, 32 levels and 5,000 values. YAML custom tags and recursive aliases are rejected.</p><div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditor(null)}>Cancel</button><button className="button button-primary" disabled={saving}>{saving ? 'SAVING…' : 'SAVE CUSTOM POLICY'}</button></div></form></Modal>}

    {selected && <Modal wide title="Custom Policy Detail" onClose={() => setSelected(null)}><div className="detail-grid"><div><span>Name</span><b>{selected.name}</b><code>{selected.slug}</code></div><div><span>Owner</span><b>{selected.owner.name}</b><code>{selected.owner.slug}</code></div><div><span>Format</span><b>{selected.format.toUpperCase()}</b></div><div><span>Status</span><Badge tone={selected.active ? 'active' : 'revoked'}>{selected.active ? 'ACTIVE' : 'INACTIVE'}</Badge></div><div className="full"><span>Description</span><p>{selected.description || 'No description provided.'}</p></div><div className="full"><span>Validated source</span><pre className="policy-document-preview">{selected.document}</pre></div></div></Modal>}
  </>
}
