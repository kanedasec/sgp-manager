import { X } from 'lucide-react'
import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: ReactNode }) {
  return <header className="page-header"><div><span className="eyebrow">{eyebrow}</span><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</header>
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge badge-${tone.toLowerCase()}`}>{children}</span>
}

export function Modal({ title, children, onClose, wide = false }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  return <div className="modal-backdrop" role="presentation" onMouseDown={e => e.target === e.currentTarget && onClose()}>
    <section className={`modal ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-head"><h2 id="modal-title">{title}</h2><button className="icon-button" onClick={onClose} aria-label="Close"><X size={18} /></button></div>
      {children}
    </section>
  </div>
}

export function Empty({ title, detail }: { title: string; detail: string }) {
  return <div className="empty"><span>00</span><h3>{title}</h3><p>{detail}</p></div>
}

export function Alert({ message, kind = 'error' }: { message?: string; kind?: 'error' | 'success' }) {
  return message ? <div className={`alert alert-${kind}`} role="alert">{message}</div> : null
}

export function Spinner() { return <div className="spinner-wrap" aria-label="Loading"><div className="spinner" /></div> }
