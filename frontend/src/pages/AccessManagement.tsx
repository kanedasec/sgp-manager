import { KeyRound, Tags, UsersRound, Waypoints } from 'lucide-react'
import { useSearchParams } from 'react-router-dom'
import { PageHeader } from '../components/ui'
import Credentials from './Credentials'
import Groups from './Groups'
import Owners from './Owners'
import Users from './Users'

export default function AccessManagement() {
  const [params, setParams] = useSearchParams()
  const requested = params.get('tab')
  const tab = ['users', 'groups', 'owners', 'credentials'].includes(requested || '') ? requested! : 'users'
  return <>
    <PageHeader eyebrow="IDENTITY / ACCESS CONTROL" title="Access Management" description="Manage human administrators and machine credentials from one control surface." />
    <div className="access-tabs" role="tablist" aria-label="Access management sections"><button role="tab" aria-selected={tab === 'users'} className={tab === 'users' ? 'active' : ''} onClick={() => setParams({ tab: 'users' })}><UsersRound size={17} /> Portal Users</button><button role="tab" aria-selected={tab === 'groups'} className={tab === 'groups' ? 'active' : ''} onClick={() => setParams({ tab: 'groups' })}><Waypoints size={17} /> Groups & Roles</button><button role="tab" aria-selected={tab === 'owners'} className={tab === 'owners' ? 'active' : ''} onClick={() => setParams({ tab: 'owners' })}><Tags size={17} /> Owners</button><button role="tab" aria-selected={tab === 'credentials'} className={tab === 'credentials' ? 'active' : ''} onClick={() => setParams({ tab: 'credentials' })}><KeyRound size={17} /> API Credentials</button></div>
    {tab === 'users' && <Users />}{tab === 'groups' && <Groups />}{tab === 'owners' && <Owners />}{tab === 'credentials' && <Credentials embedded />}
  </>
}
