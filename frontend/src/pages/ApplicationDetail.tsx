import { ArrowLeft } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, formatDate } from '../api'
import { Badge, Empty, PageHeader, Spinner } from '../components/ui'
import type { Entity, Policy } from '../types'

export default function ApplicationDetail() {
  const { id } = useParams()
  const [application, setApplication] = useState<Entity | null>(null)
  const [policies, setPolicies] = useState<Policy[]>([])
  useEffect(() => { Promise.all([api<Entity>(`/api/v1/admin/applications/${id}`), api<Policy[]>(`/api/v1/admin/bypass-policies?application_id=${id}`)]).then(([a, p]) => { setApplication(a); setPolicies(p) }) }, [id])
  if (!application) return <Spinner />
  const active = policies.filter(p => p.status === 'ACTIVE')
  const table = (rows: Policy[], empty: string) => rows.length ? <div className="table-wrap"><table><thead><tr><th>Gate policies</th><th>Validity</th><th>Status</th></tr></thead><tbody>{rows.map(p => <tr key={p.id}><td><div className="scope-summary">{p.gates.map(g => <div key={g.gate_id}><b>{g.gate_name}</b><small>{g.gate_slug}</small><div className="badge-row">{g.severities.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div></div>)}</div></td><td>{formatDate(p.valid_from)}<small>until {formatDate(p.expires_at)}</small></td><td><Badge tone={p.status}>{p.status}</Badge></td></tr>)}</tbody></table></div> : <Empty title={empty} detail="No matching policy records are available." />
  return <><Link className="back-link" to="/applications"><ArrowLeft size={16} /> Applications</Link><PageHeader eyebrow={`APPLICATION / ${application.slug}`} title={application.name} description={application.description || 'Application policy history and effective bypasses.'} action={<Badge tone={application.active ? 'active' : 'revoked'}>{application.active ? 'ACTIVE' : 'INACTIVE'}</Badge>} />
    <section className="panel"><div className="panel-head"><div><span className="eyebrow">EFFECTIVE NOW</span><h2>Active Bypasses</h2></div></div>{table(active, 'No active bypasses')}</section>
    <section className="panel"><div className="panel-head"><div><span className="eyebrow">IMMUTABLE TRAIL</span><h2>Bypass History</h2></div></div>{table(policies, 'No bypass history')}</section>
  </>
}
