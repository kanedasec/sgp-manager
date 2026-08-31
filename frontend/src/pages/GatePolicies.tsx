import {
  ArrowDown, ArrowUp, Edit3, GripVertical, Layers3, Plus, Power, Save, ShieldCheck, X,
} from 'lucide-react'
import { useEffect, useState, type DragEvent, type FormEvent } from 'react'
import { api } from '../api'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Entity, GatePolicy, GatePolicyGate } from '../types'

const severities = ['low', 'medium', 'high', 'critical']
type Editor = Partial<GatePolicy> & { gates: GatePolicyGate[] }

export default function GatePolicies() {
  const [policies, setPolicies] = useState<GatePolicy[]>([])
  const [gates, setGates] = useState<Entity[]>([])
  const [editor, setEditor] = useState<Editor | null>(null)
  const [dragging, setDragging] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const [policyItems, gateItems] = await Promise.all([
        api<GatePolicy[]>('/api/v1/admin/gate-policies'),
        api<Entity[]>('/api/v1/admin/gates?include_inactive=false'),
      ])
      setPolicies(policyItems)
      setGates(gateItems)
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not load gate policies') }
    finally { setLoading(false) }
  }

  useEffect(() => { void load() }, [])

  const edit = (policy?: GatePolicy) => setEditor(policy
    ? { ...policy, gates: policy.gates.map(gate => ({ ...gate, blocking_severities: [...gate.blocking_severities] })) }
    : { gates: [] })

  const selectedIds = editor?.gates.map(gate => gate.gate_id) || []
  const available = gates.filter(gate => !selectedIds.includes(gate.id))

  const placeGate = (gateId: string, beforeGateId?: string) => setEditor(current => {
    if (!current) return current
    const source = gates.find(gate => gate.id === gateId)
    const existing = current.gates.find(gate => gate.gate_id === gateId)
    if (!source && !existing) return current
    const next = current.gates.filter(gate => gate.gate_id !== gateId)
    const entry = existing || {
      gate_id: source!.id,
      gate_name: source!.name,
      gate_slug: source!.slug,
      position: 0,
      blocking_severities: source!.default_blocking_severities || [...severities],
    }
    const target = beforeGateId ? next.findIndex(gate => gate.gate_id === beforeGateId) : -1
    next.splice(target >= 0 ? target : next.length, 0, entry)
    return { ...current, gates: next.map((gate, position) => ({ ...gate, position })) }
  })

  const removeGate = (gateId: string) => setEditor(current => current ? {
    ...current,
    gates: current.gates.filter(gate => gate.gate_id !== gateId).map((gate, position) => ({ ...gate, position })),
  } : current)

  const moveGate = (gateId: string, offset: number) => setEditor(current => {
    if (!current) return current
    const from = current.gates.findIndex(gate => gate.gate_id === gateId)
    const to = Math.max(0, Math.min(current.gates.length - 1, from + offset))
    if (from < 0 || from === to) return current
    const next = [...current.gates]
    next.splice(to, 0, next.splice(from, 1)[0])
    return { ...current, gates: next.map((gate, position) => ({ ...gate, position })) }
  })

  const setSeverity = (gateId: string, severity: string, checked: boolean) => setEditor(current => current ? {
    ...current,
    gates: current.gates.map(gate => gate.gate_id === gateId ? {
      ...gate,
      blocking_severities: checked
        ? severities.filter(item => item === severity || gate.blocking_severities.includes(item))
        : gate.blocking_severities.filter(item => item !== severity),
    } : gate),
  } : current)

  const startDrag = (event: DragEvent, gateId: string) => {
    event.dataTransfer.effectAllowed = 'move'
    event.dataTransfer.setData('text/plain', gateId)
    setDragging(gateId)
  }
  const draggedGate = (event: DragEvent) => dragging || event.dataTransfer.getData('text/plain')

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!editor?.gates.length) return setError('A gate policy must contain at least one active gate')
    if (editor.gates.some(gate => !gate.blocking_severities.length)) return setError('Every active gate must block at least one severity')
    const form = new FormData(event.currentTarget)
    const body = {
      name: form.get('name'), slug: form.get('slug'), description: form.get('description') || null,
      gates: editor.gates.map(gate => ({ gate_id: gate.gate_id, blocking_severities: gate.blocking_severities })),
    }
    setError(''); setSaving(true)
    try {
      await api(editor.id ? `/api/v1/admin/gate-policies/${editor.id}` : '/api/v1/admin/gate-policies', {
        method: editor.id ? 'PATCH' : 'POST', body: JSON.stringify(body),
      })
      setEditor(null); await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not save gate policy') }
    finally { setSaving(false) }
  }

  const toggle = async (policy: GatePolicy) => {
    setError('')
    try {
      await api(`/api/v1/admin/gate-policies/${policy.id}`, {
        method: 'PATCH', body: JSON.stringify({ active: !policy.active }),
      })
      await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not change policy state') }
  }

  if (loading) return <Spinner />
  return <>
    <PageHeader
      eyebrow="POLICY ENGINE / REUSABLE STANDARDS"
      title="Gate Policies"
      description="Compose ordered security pipelines once, define what blocks per gate, then assign the standard to any number of applications."
      action={<button className="button button-primary" onClick={() => edit()}><Plus size={17} /> NEW GATE POLICY</button>}
    />
    <Alert message={error} />
    <section className="policy-principle">
      <ShieldCheck />
      <div><span>SERVER-SIDE ASSIGNMENT</span><b>Repositories cannot select their own standard</b><p>The workflow sends its application slug. SGP Manager resolves the assigned policy, active scans, order, and blocking severities.</p></div>
    </section>

    {policies.length ? <section className="gate-policy-grid">{policies.map(policy => <article className={!policy.active ? 'gate-policy-card policy-inactive' : 'gate-policy-card'} key={policy.id}>
      <header><div className="policy-mark"><Layers3 /></div><Badge tone={policy.active ? 'active' : 'revoked'}>{policy.active ? 'ACTIVE' : 'INACTIVE'}</Badge></header>
      <h2>{policy.name}</h2><code>{policy.slug}</code>
      <p>{policy.description || 'No description provided.'}</p>
      <div className="policy-impact"><b>{policy.application_count}</b><span>ASSIGNED<br />APPLICATIONS</span><strong>{policy.gates.length}</strong><span>ACTIVE<br />GATES</span></div>
      <div className="policy-flow">{policy.gates.map((gate, index) => <div key={gate.gate_id}>
        <span>{String(index + 1).padStart(2, '0')}</span><div><b>{gate.gate_name}</b><code>{gate.gate_slug}</code></div><div className="badge-row">{gate.blocking_severities.map(severity => <Badge key={severity} tone={severity}>{severity}</Badge>)}</div>
      </div>)}</div>
      <footer><button onClick={() => edit(policy)}><Edit3 size={15} /> Edit standard</button><button onClick={() => void toggle(policy)}><Power size={15} /> {policy.active ? 'Deactivate' : 'Activate'}</button></footer>
    </article>)}</section> : <section className="panel"><Empty title="No gate policies" detail="Create a reusable security standard before registering an application." /></section>}

    {editor && <Modal wide title={`${editor.id ? 'Edit' : 'Create'} gate policy`} onClose={() => setEditor(null)}>
      <Alert message={error} />
      <form className="form-stack" onSubmit={submit}>
        <div className="form-grid"><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editor.name} placeholder="Crown Jewels" /></label><label>Identifier / slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editor.slug} placeholder="crown-jewels" /></label><label className="full">Description<textarea name="description" rows={3} maxLength={2000} defaultValue={editor.description || ''} placeholder="Strict controls for business-critical applications." /></label></div>
        <div className="policy-editor-head"><div><span className="eyebrow">PIPELINE COMPOSER</span><h3>Active scans and blocking severities</h3></div>{available.length > 0 && <button type="button" className="button button-secondary" onClick={() => available.forEach(gate => placeGate(gate.id))}>ADD ALL ACTIVE GATES</button>}</div>
        <div className="pipeline-columns">
          <div className="pipeline-lane pipeline-active-lane" onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); placeGate(draggedGate(event)); setDragging(null) }}>
            <header><span>POLICY PIPE</span><b>{editor.gates.length} GATES</b></header>
            {editor.gates.map((gate, index) => <article key={gate.gate_id} draggable onDragStart={event => startDrag(event, gate.gate_id)} onDragEnd={() => setDragging(null)} onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); event.stopPropagation(); placeGate(draggedGate(event), gate.gate_id); setDragging(null) }} className={dragging === gate.gate_id ? 'policy-editor-gate dragging' : 'policy-editor-gate'}>
              <div className="policy-gate-main"><GripVertical className="drag-handle" /><span className="pipeline-order">{String(index + 1).padStart(2, '0')}</span><div><b>{gate.gate_name}</b><code>{gate.gate_slug}</code></div><div className="pipeline-actions"><button type="button" aria-label={`Move ${gate.gate_name} up`} disabled={index === 0} onClick={() => moveGate(gate.gate_id, -1)}><ArrowUp /></button><button type="button" aria-label={`Move ${gate.gate_name} down`} disabled={index === editor.gates.length - 1} onClick={() => moveGate(gate.gate_id, 1)}><ArrowDown /></button><button type="button" aria-label={`Remove ${gate.gate_name}`} onClick={() => removeGate(gate.gate_id)}><X /></button></div></div>
              <fieldset className="inline-severities"><legend>BLOCK ON</legend>{severities.map(severity => <label key={severity} className="mini-severity"><input type="checkbox" checked={gate.blocking_severities.includes(severity)} onChange={event => setSeverity(gate.gate_id, severity, event.target.checked)} /><span>{severity}</span></label>)}</fieldset>
            </article>)}
            {!editor.gates.length && <div className="pipeline-empty">Add at least one scanner. CI fails closed when an assigned policy has no valid gates.</div>}
          </div>
          <div className="pipeline-lane" onDragOver={event => event.preventDefault()} onDrop={event => { event.preventDefault(); removeGate(draggedGate(event)); setDragging(null) }}>
            <header><span>AVAILABLE CATALOG</span><b>{available.length} GATES</b></header>
            {available.map(gate => <article key={gate.id} draggable onDragStart={event => startDrag(event, gate.id)} onDragEnd={() => setDragging(null)} className={dragging === gate.id ? 'pipeline-gate dragging' : 'pipeline-gate'}><GripVertical className="drag-handle" /><div><b>{gate.name}</b><code>{gate.slug}</code></div><button type="button" className="pipeline-add" onClick={() => placeGate(gate.id)}>ADD</button></article>)}
            {!available.length && <div className="pipeline-empty">Every active gate is included in this standard.</div>}
          </div>
        </div>
        <p className="pipeline-note">Gate order controls workflow presentation. Each enabled gate must block at least one severity; temporary bypass policies may subtract approved severities later.</p>
        <div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditor(null)}>Cancel</button><button className="button button-primary" disabled={saving}><Save size={16} /> {saving ? 'SAVING…' : 'SAVE GATE POLICY'}</button></div>
      </form>
    </Modal>}
  </>
}
