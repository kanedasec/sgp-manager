import {
  AppWindow, ArrowDown, ArrowUp, Edit3, GripVertical, Plus, Power, Save, Search, Workflow, X,
} from 'lucide-react'
import { useEffect, useMemo, useState, type DragEvent, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth'
import { Alert, Badge, Empty, Modal, PageHeader, Spinner } from '../components/ui'
import type { Entity, Owner, SecurityPipeline } from '../types'

const severities = ['low', 'medium', 'high', 'critical']

export default function Entities({ kind }: { kind: 'applications' | 'gates' }) {
  const applicationMode = kind === 'applications'
  const [items, setItems] = useState<Entity[]>([])
  const [owners, setOwners] = useState<Owner[]>([])
  const [pipelineGateIds, setPipelineGateIds] = useState<string[]>([])
  const [pipelineDirty, setPipelineDirty] = useState(false)
  const [pipelineSaving, setPipelineSaving] = useState(false)
  const [draggingGateId, setDraggingGateId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [editing, setEditing] = useState<Partial<Entity> | null>(null)
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { user, can } = useAuth()

  const load = async () => {
    setLoading(true)
    try {
      const entities = await api<Entity[]>(`/api/v1/admin/${kind}`)
      setItems(entities)
      if (!applicationMode) {
        const ownerItems = await api<Owner[]>('/api/v1/admin/owner-labels')
        setOwners(ownerItems)
        if (user?.role === 'ADMIN') {
          const pipeline = await api<SecurityPipeline>('/api/v1/admin/security-pipeline')
          setPipelineGateIds(pipeline.gates.map(gate => gate.id))
          setPipelineDirty(false)
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not load records')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [kind, user?.role])

  const filtered = useMemo(
    () => items.filter(x => `${x.name} ${x.slug}`.toLowerCase().includes(query.toLowerCase())),
    [items, query],
  )
  const pipelineItems = pipelineGateIds
    .map(id => items.find(item => item.id === id))
    .filter((item): item is Entity => !!item)
  const availablePipelineItems = items.filter(
    item => item.active && !pipelineGateIds.includes(item.id),
  )

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

  const toggle = async (item: Entity) => {
    try {
      await api(`/api/v1/admin/${kind}/${item.id}`, { method: 'PATCH', body: JSON.stringify({ active: !item.active }) })
      await load()
    } catch (e) { setError(e instanceof Error ? e.message : 'Could not change state') }
  }

  const placeGate = (gateId: string, beforeGateId?: string) => {
    setPipelineGateIds(current => {
      const next = current.filter(id => id !== gateId)
      const target = beforeGateId ? next.indexOf(beforeGateId) : -1
      next.splice(target >= 0 ? target : next.length, 0, gateId)
      return next
    })
    setPipelineDirty(true)
  }

  const removeGate = (gateId: string) => {
    setPipelineGateIds(current => current.filter(id => id !== gateId))
    setPipelineDirty(true)
  }

  const moveGate = (gateId: string, offset: number) => {
    setPipelineGateIds(current => {
      const from = current.indexOf(gateId)
      const to = Math.max(0, Math.min(current.length - 1, from + offset))
      if (from < 0 || from === to) return current
      const next = [...current]
      next.splice(from, 1)
      next.splice(to, 0, gateId)
      return next
    })
    setPipelineDirty(true)
  }

  const startDrag = (event: DragEvent, gateId: string) => {
    event.dataTransfer.effectAllowed = 'move'
    event.dataTransfer.setData('text/plain', gateId)
    setDraggingGateId(gateId)
  }

  const draggedGate = (event: DragEvent) => draggingGateId || event.dataTransfer.getData('text/plain')

  const savePipeline = async () => {
    if (!pipelineGateIds.length) {
      setError('The security pipeline must contain at least one gate')
      return
    }
    setError(''); setPipelineSaving(true)
    try {
      await api('/api/v1/admin/security-pipeline', {
        method: 'PATCH', body: JSON.stringify({ gate_ids: pipelineGateIds }),
      })
      await load()
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not save the security pipeline')
    } finally {
      setPipelineSaving(false)
    }
  }

  const label = applicationMode ? 'Application' : 'Security Gate'
  const canCreate = applicationMode ? user?.role === 'ADMIN' : owners.some(owner => can('gates', 'create', owner.slug))
  const canEdit = (item: Entity) => applicationMode ? user?.role === 'ADMIN' : !!item.owner && can('gates', 'edit', item.owner.slug)
  if (loading) return <Spinner />

  return <>
    <PageHeader
      eyebrow={`INVENTORY / ${applicationMode ? 'PROTECTED ASSETS' : 'ENFORCEMENT POINTS'}`}
      title={applicationMode ? 'Applications' : 'Security Gates'}
      description={applicationMode ? 'Services and products that consume security policy decisions.' : 'Owner-scoped controls, blocking defaults and the active CI security pipe.'}
      action={canCreate ? <button className="button button-primary" onClick={() => setEditing({})}><Plus size={17} /> NEW {label.toUpperCase()}</button> : undefined}
    />
    <Alert message={error} />

    {!applicationMode && user?.role === 'ADMIN' && <section className="panel pipeline-builder">
      <div className="section-toolbar">
        <div><span className="eyebrow">PIPELINE / GLOBAL STANDARD</span><h2>Security pipe</h2><p>Drag active gates into the pipe and arrange their policy order. Scanner jobs start only after this configuration is resolved.</p></div>
        <button className="button button-primary" disabled={!pipelineDirty || pipelineSaving || !pipelineGateIds.length} onClick={() => void savePipeline()}><Save size={17} /> {pipelineSaving ? 'SAVING…' : 'SAVE PIPE'}</button>
      </div>
      <div className="pipeline-columns">
        <div
          className="pipeline-lane pipeline-active-lane"
          onDragOver={event => event.preventDefault()}
          onDrop={event => { event.preventDefault(); placeGate(draggedGate(event)); setDraggingGateId(null) }}
        >
          <header><span>ACTIVE PIPE</span><b>{pipelineItems.length} GATES</b></header>
          {pipelineItems.map((item, index) => <article
            key={item.id}
            draggable
            onDragStart={event => startDrag(event, item.id)}
            onDragEnd={() => setDraggingGateId(null)}
            onDragOver={event => event.preventDefault()}
            onDrop={event => { event.preventDefault(); event.stopPropagation(); placeGate(draggedGate(event), item.id); setDraggingGateId(null) }}
            className={draggingGateId === item.id ? 'pipeline-gate dragging' : 'pipeline-gate'}
          >
            <GripVertical className="drag-handle" />
            <span className="pipeline-order">{String(index + 1).padStart(2, '0')}</span>
            <div><b>{item.name}</b><code>{item.slug}</code></div>
            <div className="pipeline-actions">
              <button aria-label={`Move ${item.name} up`} disabled={index === 0} onClick={() => moveGate(item.id, -1)}><ArrowUp /></button>
              <button aria-label={`Move ${item.name} down`} disabled={index === pipelineItems.length - 1} onClick={() => moveGate(item.id, 1)}><ArrowDown /></button>
              <button aria-label={`Remove ${item.name} from pipe`} onClick={() => removeGate(item.id)}><X /></button>
            </div>
          </article>)}
          {!pipelineItems.length && <div className="pipeline-empty">Drag at least one active gate here. An empty pipe cannot be saved.</div>}
        </div>

        <div
          className="pipeline-lane"
          onDragOver={event => event.preventDefault()}
          onDrop={event => { event.preventDefault(); removeGate(draggedGate(event)); setDraggingGateId(null) }}
        >
          <header><span>AVAILABLE</span><b>{availablePipelineItems.length} GATES</b></header>
          {availablePipelineItems.map(item => <article
            key={item.id}
            draggable
            onDragStart={event => startDrag(event, item.id)}
            onDragEnd={() => setDraggingGateId(null)}
            className={draggingGateId === item.id ? 'pipeline-gate dragging' : 'pipeline-gate'}
          >
            <GripVertical className="drag-handle" />
            <div><b>{item.name}</b><code>{item.slug}</code></div>
            <button className="pipeline-add" onClick={() => placeGate(item.id)}>ADD</button>
          </article>)}
          {!availablePipelineItems.length && <div className="pipeline-empty">Every active gate is already in the pipe.</div>}
        </div>
      </div>
      <p className="pipeline-note">Only administrators can change the global pipe. Inactive gates are excluded. Unknown workflow implementations fail closed during CI preflight.</p>
    </section>}

    <section className="panel"><div className="toolbar"><label className="search"><Search size={17} /><input aria-label={`Search ${kind}`} placeholder={`Search ${kind}…`} value={query} onChange={e => setQuery(e.target.value)} /></label><span>{filtered.length} RECORDS</span></div>
      {filtered.length ? <div className="entity-grid">{filtered.map(item => <article className={`entity-card ${!item.active ? 'entity-disabled' : ''}`} key={item.id} onClick={() => applicationMode && navigate(`/applications/${item.id}`)}><div className="entity-icon">{applicationMode ? <AppWindow /> : <Workflow />}</div><div className="entity-title"><div><h2>{item.name}</h2><code>{item.slug}</code></div><Badge tone={item.active ? 'active' : 'revoked'}>{item.active ? 'ACTIVE' : 'INACTIVE'}</Badge></div>{item.owner && <div className="owner-stamp">OWNER / <b>{item.owner.slug}</b></div>}<p>{item.description || 'No description provided.'}</p>{!applicationMode && <div className="gate-defaults"><span>BLOCKS BY DEFAULT</span><div className="badge-row">{item.default_blocking_severities?.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div>{item.pipeline_position != null && <small>PIPE POSITION / {String(item.pipeline_position + 1).padStart(2, '0')}</small>}</div>}{canEdit(item) && <div className="entity-actions"><button onClick={e => { e.stopPropagation(); setEditing(item) }}><Edit3 size={15} /> Edit</button><button onClick={e => { e.stopPropagation(); void toggle(item) }}><Power size={15} /> {item.active ? 'Disable' : 'Enable'}</button></div>}</article>)}</div> : <Empty title={`No ${kind} found`} detail={`Create the first ${label.toLowerCase()} or change the search term.`} />}
    </section>
    {editing && <Modal title={`${editing.id ? 'Edit' : 'Create'} ${label}`} onClose={() => setEditing(null)}><Alert message={error} /><form className="form-stack" onSubmit={submit}><label>Name<input name="name" required minLength={2} maxLength={120} defaultValue={editing.name} /></label><label>Identifier / slug<input name="slug" required pattern="[a-z0-9]+(?:-[a-z0-9]+)*" maxLength={100} defaultValue={editing.slug} placeholder="payment-api" /></label>{!applicationMode && <label>Owner<select name="owner_id" required defaultValue={editing.owner_id || ''}><option value="" disabled>Select owner</option>{owners.filter(owner => editing.id ? can('gates', 'edit', owner.slug) : can('gates', 'create', owner.slug)).map(owner => <option key={owner.id} value={owner.id}>{owner.name} — {owner.slug}</option>)}</select></label>}<label>Description<textarea name="description" maxLength={2000} rows={4} defaultValue={editing.description || ''} /></label>{!applicationMode && <fieldset className="severity-picker"><legend>Default blocking severities</legend>{severities.map(s => <label key={s} className={`severity-option severity-${s}`}><input type="checkbox" name={`default_${s}`} defaultChecked={editing.id ? editing.default_blocking_severities?.includes(s) : true} /><span>{s.toUpperCase()}</span></label>)}<p className="field-help">Findings at these severities block the gate unless an active application bypass explicitly removes them.</p></fieldset>}<div className="form-actions"><button type="button" className="button button-secondary" onClick={() => setEditing(null)}>Cancel</button><button className="button button-primary">Save {label}</button></div></form></Modal>}
  </>
}
