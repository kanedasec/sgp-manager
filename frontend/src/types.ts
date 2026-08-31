export type Owner = { id: string; name: string; slug: string; description?: string | null; active: boolean; created_at: string; updated_at: string }
export type GatePolicySummary = { id: string; name: string; slug: string; active: boolean }
export type Entity = { id: string; name: string; slug: string; description?: string | null; active: boolean; created_at: string; updated_at: string; owner_id?: string; owner?: Owner; default_blocking_severities?: string[]; gate_policy_id?: string; gate_policy?: GatePolicySummary }
export type GatePolicyGate = { gate_id: string; gate_name: string; gate_slug: string; position: number; blocking_severities: string[] }
export type GatePolicy = { id: string; name: string; slug: string; description?: string | null; active: boolean; gates: GatePolicyGate[]; application_count: number; created_at: string; updated_at: string }
export type PolicyGate = { gate_id: string; gate_name: string; gate_slug: string; severities: string[] }
export type Policy = {
  id: string; application_id: string; application_name: string; application_slug: string; owner_id: string; owner_name: string; owner_slug: string; gates: PolicyGate[];
  justification: string; valid_from: string; expires_at: string; created_by: string; created_at: string; updated_at: string;
  revoked_at?: string | null; revoked_by?: string | null; revoke_reason?: string | null; status: string
}
export type Credential = { id: string; name: string; prefix: string; scopes: string[]; active: boolean; created_at: string; created_by: string; last_used_at?: string | null; expires_at?: string | null; api_key?: string }
export type Audit = { id: string; event_type: string; actor_type: string; actor_id?: string; entity_type?: string; entity_id?: string; timestamp: string; metadata: Record<string, unknown>; source_ip?: string }
export type DashboardData = { applications: number; gates: number; active_bypasses: number; expiring_soon: number; recently_expired: number; expiring_policies: Policy[] }
export type GroupSummary = { id: string; name: string; slug: string; active: boolean }
export type AdminUser = { id: string; username: string; display_name: string; email: string; role: string; active: boolean; created_at: string; updated_at: string; groups: GroupSummary[] }
export type AccessGroup = { id: string; name: string; slug: string; description?: string | null; active: boolean; permissions: string[]; user_count: number; created_at: string; updated_at: string }
