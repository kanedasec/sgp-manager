import { AppWindow, Clock3, ShieldCheck, TimerReset, Workflow } from 'lucide-react'
import { useEffect, useState } from 'react'
import { api, formatDate } from '../api'
import { Badge, Empty, PageHeader, Spinner } from '../components/ui'
import type { DashboardData } from '../types'

export default function Dashboard() {
  const [data, setData] = useState<DashboardData | null>(null)
  useEffect(() => { api<DashboardData>('/api/v1/admin/dashboard').then(setData) }, [])
  if (!data) return <Spinner />
  const cards = [
    ['Applications', data.applications, AppWindow, 'registered & active'], ['Security Gates', data.gates, Workflow, 'enforcement points'],
    ['Active Bypasses', data.active_bypasses, ShieldCheck, 'effective right now'], ['Expiring Soon', data.expiring_soon, TimerReset, 'within configured window'],
  ] as const
  return <><PageHeader eyebrow="CONTROL OVERVIEW / REAL TIME" title="Dashboard" description="A compact view of temporary exceptions across your delivery estate." />
    <section className="metric-grid">{cards.map(([label, value, Icon, note], i) => <article className="metric-card" key={label}><div className="metric-top"><span>0{i + 1}</span><Icon size={20} /></div><strong>{value.toString().padStart(2, '0')}</strong><h2>{label}</h2><p>{note}</p></article>)}</section>
    <section className="panel"><div className="panel-head"><div><span className="eyebrow">NEXT 7 DAYS</span><h2>Bypasses expiring soon</h2></div><div className="recent-stat"><Clock3 size={18} /><span>Recently expired</span><b>{data.recently_expired}</b></div></div>
      {data.expiring_policies.length ? <div className="table-wrap"><table><thead><tr><th>Application</th><th>Gate policies</th><th>Expiration</th><th>Status</th></tr></thead><tbody>{data.expiring_policies.map(p => <tr key={p.id}><td><b>{p.application_name}</b><small>{p.application_slug}</small></td><td><div className="scope-summary compact">{p.gates.map(g => <div key={g.gate_id}><code>{g.gate_slug}</code><div className="badge-row">{g.severities.map(s => <Badge key={s} tone={s}>{s}</Badge>)}</div></div>)}</div></td><td>{formatDate(p.expires_at)}</td><td><Badge tone={p.status}>{p.status}</Badge></td></tr>)}</tbody></table></div> : <Empty title="No urgent expirations" detail="No active bypass will expire inside the configured window." />}
    </section>
  </>
}
