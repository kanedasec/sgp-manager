import { FileClock, Search } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { api, formatDate } from '../api'
import { Badge, Empty, PageHeader, Spinner } from '../components/ui'
import type { Audit } from '../types'

export default function AuditLogs() {
  const [items, setItems] = useState<Audit[]>([])
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => { api<Audit[]>('/api/v1/admin/audit-logs?limit=250').then(setItems).finally(() => setLoading(false)) }, [])
  const filtered = useMemo(() => items.filter(x => JSON.stringify(x).toLowerCase().includes(query.toLowerCase())), [items, query])
  if (loading) return <Spinner />
  return <><PageHeader eyebrow="AUDITABILITY / APPEND ONLY" title="Audit Logs" description="Administrative security events with actor, target, source and sanitized context." />
    <section className="panel"><div className="toolbar"><label className="search"><Search size={17} /><input aria-label="Search audit events" placeholder="Search event, actor or entity…" value={query} onChange={e => setQuery(e.target.value)} /></label><span>{filtered.length} EVENTS</span></div>
      {filtered.length ? <div className="audit-stream">{filtered.map(item => <article key={item.id}><div className="audit-line"><div className="audit-icon"><FileClock size={17} /></div><div><h2>{item.event_type.replaceAll('_', ' ')}</h2><span>{formatDate(item.timestamp)}</span></div><Badge tone={item.actor_type === 'USER' ? 'active' : 'neutral'}>{item.actor_type}</Badge></div><div className="audit-facts"><span>ACTOR <code>{item.actor_id?.slice(0, 12) || 'system'}</code></span><span>ENTITY <code>{item.entity_type || '—'} / {item.entity_id?.slice(0, 12) || '—'}</code></span><span>SOURCE <code>{item.source_ip || 'internal'}</code></span></div>{Object.keys(item.metadata).length > 0 && <pre>{JSON.stringify(item.metadata, null, 2)}</pre>}</article>)}</div> : <Empty title="No audit events" detail="Events will appear after administrative activity." />}
    </section>
  </>
}
