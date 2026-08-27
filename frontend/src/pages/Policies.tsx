import { Eye, Filter, Plus, ShieldAlert, ShieldOff } from 'lucide-react'
import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { api, formatDate, toUtc } from '../api'
import { useAuth } from '../auth'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Entity, Owner, Policy } from '../types'

const severities = ['low', 'medium', 'high', 'critical']
const defaultExpiry = () => { const d = new Date(Date.now() + 30 * 86400000); d.setSeconds(0, 0); return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16) }

export default function Policies() {
  const [policies, setPolicies] = useState<Policy[]>([])
  const [applications, setApplications] = useState<Entity[]>([])
  const [gates, setGates] = useState<Entity[]>([])
  const [owners, setOwners] = useState<Owner[]>([])
  const [loading, setLoading] = useState(true)
  const [createOpen, setCreateOpen] = useState(false)
  const [selected, setSelected] = useState<Policy | null>(null)
  const [gatePolicies, setGatePolicies] = useState<Record<string, string[]>>({})
  const [selectedOwner, setSelectedOwner] = useState('')
  const [filters, setFilters] = useState({ application: '', owner: '', gate: '', status: '', validFrom: '', validUntil: '' })
  const [error, setError] = useState('')
  const { can } = useAuth()
  const load = () => Promise.all([
    api<Policy[]>('/api/v1/admin/bypass-policies'),
    api<Entity[]>('/api/v1/admin/applications?include_inactive=false'),
    api<Entity[]>('/api/v1/admin/gates?include_inactive=false'),
    api<Owner[]>('/api/v1/admin/owner-labels'),
  ]).then(([p, a, g, o]) => { setPolicies(p); setApplications(a); setGates(g); setOwners(o) }).finally(() => setLoading(false))
  useEffect(() => { void load() }, [])

  const filtered = useMemo(() => policies.filter(p =>
    (!filters.application || p.application_id === filters.application) &&
    (!filters.owner || p.owner_id === filters.owner) &&
    (!filters.gate || p.gates.some(g => g.gate_id === filters.gate)) &&
    (!filters.status || p.status === filters.status) &&
    (!filters.validFrom || new Date(p.expires_at) > new Date(filters.validFrom)) &&
    (!filters.validUntil || new Date(p.valid_from) < new Date(`${filters.validUntil}T23:59:59`))
  ), [policies, filters])

  const openCreate = () => { setError(''); setGatePolicies({}); setSelectedOwner(''); setCreateOpen(true) }
  const toggleGate = (gate: Entity, enabled: boolean) => setGatePolicies(current => {
    const next = { ...current }
    if (enabled) next[gate.id] = []
    else delete next[gate.id]
    return next
  })
  const toggleSeverity = (gateId: string, severity: string, enabled: boolean) => setGatePolicies(current => ({
    ...current,
    [gateId]: enabled ? [...(current[gateId] || []), severity] : (current[gateId] || []).filter(item => item !== severity),
  }))

  const create = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('')
    const form = new FormData(event.currentTarget)
    const chosen = Object.entries(gatePolicies).map(([gate_id, selectedSeverities]) => ({ gate_id, severities: selectedSeverities }))
    if (!chosen.length) { setError('Select at least one security gate.'); return }
    if (chosen.some(item => !item.severities.length)) { setError('Select at least one severity for every selected gate.'); return }
    try {
      await api('/api/v1/admin/bypass-policies', { method: 'POST', body: JSON.stringify({
        application_id: form.get('application_id'), owner_id: form.get('owner_id'), gates: chosen,
        expires_at: toUtc(String(form.get('expires_at'))), justification: form.get('justification'),
      }) })
      setCreateOpen(false); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not create policy') }
  }
  const revoke = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); if (!selected) return; setError('')
    const reason = new FormData(event.currentTarget).get('reason')
    try {
      await api(`/api/v1/admin/bypass-policies/${selected.id}/revoke`, { method: 'POST', body: JSON.stringify({ reason }) })
      setSelected(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not revoke policy') }
  }

  if (loading) return <Spinner />
  const creatableOwners = owners.filter(owner => can('policies', 'create', owner.slug))
  return <>
    <PageHeader eyebrow="EXCEPTIONS / OWNER SCOPED" title="Bypass Policies" description="Grant owner-scoped, auditable exceptions across one or more gates managed by the same owner." action={creatableOwners.length ? <button className="button button-primary" onClick={openCreate}><Plus size={17} /> CREATE BYPASS</button> : undefined} />
    <section className="panel">
      <div className="filter-bar"><span><Filter size={17} /> FILTER</span><select aria-label="Filter by application" value={filters.application} onChange={e => setFilters({ ...filters, application: e.target.value })}><option value="">All applications</option>{applications.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select><select aria-label="Filter by owner" value={filters.owner} onChange={e => setFilters({ ...filters, owner: e.target.value })}><option value="">All owners</option>{owners.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select><select aria-label="Filter by gate" value={filters.gate} onChange={e => setFilters({ ...filters, gate: e.target.value })}><option value="">All gates</option>{gates.map(x => <option key={x.id} value={x.id}>{x.name}</option>)}</select><select aria-label="Filter by status" value={filters.status} onChange={e => setFilters({ ...filters, status: e.target.value })}><option value="">All statuses</option><option>ACTIVE</option><option>SCHEDULED</option><option>EXPIRED</option><option>REVOKED</option></select><label className="compact-date">Valid after<input aria-label="Validity starts after" type="date" value={filters.validFrom} onChange={e => setFilters({ ...filters, validFrom: e.target.value })} /></label><label className="compact-date">Valid before<input aria-label="Validity ends before" type="date" value={filters.validUntil} onChange={e => setFilters({ ...filters, validUntil: e.target.value })} /></label><b>{filtered.length} RESULTS</b></div>
      {filtered.length ? <div className="table-wrap"><table><thead><tr><th>Application / Owner</th><th>Gate policies</th><th>Expiration</th><th>Status</th><th /></tr></thead><tbody>{filtered.map(p => <tr key={p.id}><td><b>{p.application_name}</b><small>{p.application_slug}</small><span className="owner-inline">OWNER / {p.owner_slug}</span></td><td><div className="scope-summary">{p.gates.map(g => <div key={g.gate_id}><code>{g.gate_slug}</code><div className="badge-row">{g.severities.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div></div>)}</div></td><td>{formatDate(p.expires_at)}</td><td><Badge tone={p.status}>{p.status}</Badge></td><td><div className="row-actions"><button className="table-action" onClick={() => { setError(''); setSelected(p) }}><Eye size={16} /> View</button>{!['REVOKED', 'EXPIRED'].includes(p.status) && can('policies', 'edit', p.owner_slug) && <button className="table-action danger-action" onClick={() => { setError(''); setSelected(p) }}><ShieldOff size={16} /> Revoke</button>}</div></td></tr>)}</tbody></table></div> : <Empty title="No bypass policies" detail="No policies match your owner scope or the current filters. Absence always means no bypass." />}
    </section>

    {createOpen && <Modal title="Create Multi-Gate Bypass Policy" onClose={() => setCreateOpen(false)} wide><Alert message={error} /><div className="warning"><ShieldAlert /><div><b>This changes pipeline enforcement</b><p>Every selected gate must belong to the policy owner. Severities remain explicit and time-bound.</p></div></div><form className="form-grid" onSubmit={create}><label>Application<select name="application_id" required defaultValue=""><option value="" disabled>Select application</option>{applications.map(x => <option key={x.id} value={x.id}>{x.name} — {x.slug}</option>)}</select></label><label>Policy owner<select name="owner_id" required value={selectedOwner} onChange={e => { setSelectedOwner(e.target.value); setGatePolicies({}) }}><option value="" disabled>Select owner</option>{creatableOwners.map(owner => <option key={owner.id} value={owner.id}>{owner.name} — {owner.slug}</option>)}</select></label><fieldset className="gate-policy-picker full"><legend>Security gates and bypass severities</legend><p className="field-help">Only gates owned by the selected policy owner are eligible. Nothing is preselected.</p>{gates.filter(gate => gate.owner_id === selectedOwner).map(gate => { const enabled = Object.hasOwn(gatePolicies, gate.id); return <article className={`gate-policy-row ${enabled ? 'gate-policy-selected' : ''}`} key={gate.id}><label className="gate-toggle"><input type="checkbox" checked={enabled} onChange={e => toggleGate(gate, e.target.checked)} /><span><b>{gate.name}</b><code>{gate.slug}</code><small>Blocks: {(gate.default_blocking_severities || []).join(', ')}</small></span></label><div className="inline-severities">{severities.map(severity => <label key={severity} className={`mini-severity mini-${severity}`}><input type="checkbox" disabled={!enabled} checked={(gatePolicies[gate.id] || []).includes(severity)} onChange={e => toggleSeverity(gate.id, severity, e.target.checked)} /><span>{severity}</span></label>)}</div></article>})}{selectedOwner && !gates.some(gate => gate.owner_id === selectedOwner) && <div className="info-note">No visible gates belong to this owner. A <code>view-gates</code> role may be required.</div>}</fieldset><label>Valid until<input name="expires_at" type="datetime-local" required defaultValue={defaultExpiry()} /></label><div className="policy-count"><b>{Object.keys(gatePolicies).length}</b><span>GATES SELECTED</span></div><label className="full">Justification<textarea name="justification" required minLength={10} maxLength={4000} rows={5} placeholder="Explain why this exception is necessary, its context, and remediation plan." /></label><div className="form-actions full"><button type="button" className="button button-secondary" onClick={() => setCreateOpen(false)}>Cancel</button><button className="button button-danger">Create Bypass Policy</button></div></form></Modal>}

    {selected && <Modal title="Bypass Policy Detail" onClose={() => setSelected(null)} wide><Alert message={error} /><div className="detail-grid"><div><span>Application</span><b>{selected.application_name}</b><code>{selected.application_slug}</code></div><div><span>Owner</span><b>{selected.owner_name}</b><code>{selected.owner_slug}</code></div><div><span>Status</span><Badge tone={selected.status}>{selected.status}</Badge></div><div><span>Valid from</span><b>{formatDate(selected.valid_from)}</b></div><div><span>Expires</span><b>{formatDate(selected.expires_at)}</b></div><div className="full"><span>Gate policies</span><div className="detail-scopes">{selected.gates.map(g => <article key={g.gate_id}><div><b>{g.gate_name}</b><code>{g.gate_slug}</code></div><div className="badge-row">{g.severities.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div></article>)}</div></div><div className="full"><span>Justification</span><p>{selected.justification}</p></div>{selected.revoke_reason && <div className="full revoked-box"><span>Revocation reason</span><p>{selected.revoke_reason}</p></div>}</div>{!['REVOKED', 'EXPIRED'].includes(selected.status) && can('policies', 'edit', selected.owner_slug) && <form className="revoke-form" onSubmit={revoke}><label>Manually revoke this entire policy<textarea name="reason" required minLength={5} maxLength={2000} rows={3} placeholder="Revocation reason is required for the audit trail." /></label><button className="button button-danger"><ShieldOff size={16} /> REVOKE POLICY</button></form>}</Modal>}
  </>
}
