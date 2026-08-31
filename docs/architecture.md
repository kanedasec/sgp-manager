# Architecture

## Components

The product is a modular monolith with three runtime containers:

```text
Browser
  -> unprivileged nginx :3000
       -> React SPA
       -> /api, /docs and operational endpoint proxy
            -> FastAPI :8000
                 -> SQLAlchemy -> PostgreSQL :5432
                                   (isolated database network only)

Pipeline
  -> nginx :3000 -> FastAPI :8000 (private Compose network)
       -> API credential authentication
       -> policy evaluation
       -> minimal JSON decision
```

The backend is separated into HTTP routes (`api`), input/output contracts (`schemas`), persistence entities (`models`), reusable queries (`repositories`), domain actions (`services`), and cross-cutting configuration/security (`core`). It remains a single deployable process and transaction boundary.

## Data model

- `User`: local identity, Argon2id password digest, `ADMIN`/`USER` account role, active flag, and many-to-many access-group memberships.
- `OwnerLabel`: reusable authorization boundary such as AppSec, Architecture, or Quality. Labels are disabled rather than deleted.
- `AccessGroup`: administrator-managed collection assigned to users. Active groups grant additive permissions.
- `GroupPermission`: normalized `(action, resource, owner)` grant. A null owner represents the global `:all` scope.
- `Application`: stable unique slug used by pipelines and one required reusable gate-policy assignment; deactivation preserves history and prevents pipeline discovery.
- `Gate`: stable unique slug for a security control, required owner, policy-authoring severity defaults, and active flag.
- `GatePolicy`: reusable named security standard assigned to one or more applications.
- `GatePolicyGate`: ordered gate membership and the policy-specific blocking severity set. A gate appears at most once per policy and positions are contiguous at the API boundary.
- `BypassPolicy`: application-level, owner-scoped, auditable policy header containing justification, half-open validity window, creator and revocation trail.
- `BypassPolicyGate`: one gate scope inside a policy, with an independent JSON severity set. A policy may contain many gate scopes but a gate appears at most once in that policy.
- `ApiCredential`: human label, non-secret prefix, HMAC digest, `policy:read` scopes array, usage/expiry timestamps, and active flag.
- `AuditLog`: actor, event, target, timestamp, sanitized metadata, and source IP. There is no administrative delete API.

All primary keys are UUIDs. All timestamps use timezone-aware database columns and API values are normalized to UTC. The frontend renders dates using the browser locale.

Migration `20260826_0003` makes the earlier gate-default field explicit as `default_blocking_severities`. Existing non-empty selections are preserved; empty selections are upgraded to all four severities so previously unconfigured gates become fail-closed rather than silently permitting findings.

Migration `20260826_0004` adds owner labels, group permissions, memberships, and required owner foreign keys for gates and policies. Existing gates and policies are assigned to a deterministic `unassigned` owner so the migration is non-destructive; an administrator can later reclassify them. The database stores permission owner UUIDs rather than slugs, so renaming an owner does not detach existing grants.

### Derived policy state

State is not persisted because time changes independently of writes:

1. `REVOKED` when `revoked_at` exists.
2. `EXPIRED` when `expires_at <= now`.
3. `ACTIVE` when `valid_from <= now < expires_at`.
4. `SCHEDULED` when the approved window starts in the future.

Only step 3 is effective for pipeline evaluation.

### Conflict rule

Two non-revoked gate scopes for the same `(application_id, gate_id)` cannot have overlapping half-open windows. Fast rejection in the policy service gives a useful error. PostgreSQL's `btree_gist` exclusion constraint on `BypassPolicyGate` closes the concurrent-request race at the authoritative storage layer, including when concurrent requests create different multi-gate policy groups.

Revoking a policy marks its header and every gate scope in one transaction. This releases all of its ranges from the constraint predicate without deleting history.

## Authentication

### Administrators

`POST /api/v1/auth/login` validates an Argon2id digest and issues a short-lived signed JWT containing user ID, role, issue time, expiry, and token type. Protected routes re-read the active user, so disabling an account takes effect immediately even if a token has not expired. The SPA keeps the token in `sessionStorage`, limiting persistence to the browser tab/session; production ingress should always use TLS.

The same successful login issues a `SameSite=Strict`, HttpOnly cookie used only to authorize `/docs`, `/redoc`, and `/openapi.json`. Administrative APIs do not accept this cookie and still require the explicit Bearer token, limiting CSRF exposure. Portal logout deletes the documentation cookie. In HTTPS deployments `SESSION_COOKIE_SECURE` must be enabled.

Bootstrap creates the first administrator only when no user exists. Compose supplies a documented fallback identity and marks that database record with `must_change_password=true`. Login issues a limited Bearer token but no documentation cookie; the common current-user dependency rejects all domain/admin routes until `POST /api/v1/auth/change-password` verifies the current password, hashes a different password, clears the flag, and writes an audit event. `/auth/me` remains available so the SPA can restore and route the restricted session. No password appears in structured logs or audit metadata.

Migration `20260827_0005` adds the persisted first-login state. Existing accounts are migrated with `false` so an upgrade does not unexpectedly lock established administrators; newly bootstrapped installations use `true`.

Migration `20260831_0006` adds the nullable unique pipeline position. Existing
active `sast`, `secrets`, and `sca` gates are backfilled at positions 0, 1, and
2. Other gates remain outside the pipe until explicitly selected by an
administrator.

Migration `20260831_0007` creates reusable gate policies, copies the existing
global pipe and each gate's blocking defaults into a deterministic **Default
Security Policy**, assigns every existing application to it, and removes the
obsolete gate-level pipeline position. The migration therefore preserves the
effective scanner selection and severity behavior while changing ownership of
that configuration from a global list to an application-assigned standard.

## Portal authorization

`ADMIN` is a protected break-glass/management role with implicit access to all portal functions. A `USER` has no gate or policy access by default. Its effective permissions are the union of permissions from all assigned active groups; inactive groups grant nothing.

Permission names are rendered as `<action>-<resource>:<owner-slug>`, for example:

```text
view-policies:all
create-policies:appsec
edit-policies:appsec
view-gates:quality
```

The allowed action set is `view`, `create`, and `edit`; the current resource set is `gates` and `policies`. `:all` is a wildcard owner scope, not an owner label, and the slug `all` is reserved. `edit-policies` covers normal edits and manual revocation. Permission checks use owner UUIDs internally.

List queries are filtered to owners for which the actor has `view`; direct-object requests independently verify the same permission. Creation checks the requested owner. Owner changes check edit permission for both the source and destination boundary. Access management, dashboard, application mutation, API credentials, and audit logs are administrator-only. The application catalog is readable by authenticated users because it is shared context for authorized gate and policy work.

Gate-policy management and application assignment are administrator-only because
a reusable standard may affect several applications and cross gate-owner
boundaries. A policy assigned to an active application cannot be deactivated.
A gate referenced by any gate policy cannot be renamed or deactivated until an
administrator removes it from those policies. These constraints prevent a gate
catalog edit from silently changing or invalidating application pipelines.

A multi-gate bypass policy can contain only gates whose owner equals the policy owner. This is a deliberate isolation rule: without it, a user with `create-policies:appsec` could place a Quality-owned gate into an AppSec policy and cross the authorization boundary.

### Pipelines

A pipeline submits an opaque API key using `X-API-Key`. The server calculates a deterministic HMAC-SHA-256 digest with a separate environment-held pepper, looks up only the digest, checks active/expiry/scope, and updates `last_used_at`. The raw key exists only in the create response.

The scopes JSON array begins with `policy:read`, leaving room for application filters and additional machine operations later.

## Administrative flow

Administrative create/update/revoke actions and login outcomes write audit records in the same database transaction as the corresponding state change where applicable. Metadata is allow-limited by a recursive sensitive-key scrubber. Physical deletion is not exposed.

Local users, groups, owners, and machine credentials share the portal's **Access Management** area but remain separate domain objects. User administration prevents self-deactivation/self-downgrade and protects the last active administrator. Gate blocking defaults are enforcement inputs; bypass forms deliberately preselect nothing so every exception remains explicit.

## Pipeline flow

1. Authenticate the API key from a header and rate-limit the caller by source address.
2. Resolve an active application, its active assigned gate policy, and that policy's ordered gates through `/resolve-pipeline`.
3. Validate that every returned gate has a known workflow implementation; fail before scanning otherwise.
4. Run the selected independent scanners without exposing the API credential to their jobs.
5. Load each selected gate's policy-specific blocking severities.
6. Query policy gate scopes with `valid_from <= now < expires_at` and no policy/scope revocation.
7. For each selected gate calculate `blocking = defaults - effective bypass severities`.
8. Return only the gate slug and final blocking severities.

For enforcement, an unknown or inactive application receives unchanged gate defaults, which is fail-closed. An unknown requested gate returns `404`. Invalid authentication returns `401`; rate limiting returns `429`; generic errors return `500` with a request ID. Every non-success outcome must be interpreted by pipeline code as block/no authorization. The older `/evaluate` endpoint remains available to inspect active bypass entries directly.

## Security and operations

- Restrictive CORS, CSP and browser security headers are configured.
- Request logs are JSON with correlation ID, route, status, and duration; request bodies and credentials are never logged.
- `/health` checks process liveness and `/ready` executes `SELECT 1`.
- Prometheus metrics report request counts and durations at `/metrics`.
- Alembic is the only production schema creation path and runs before API startup.
- A one-shot, network-disabled `secrets-init` container creates the PostgreSQL password, JWT secret, and API-key pepper from `/dev/urandom` when the `runtime_secrets` volume is empty. Values are never logged and are mounted read-only into consumers. Explicit environment overrides are copied only during initial volume creation.
- Backend and frontend run unprivileged. PostgreSQL publishes no port, joins only the `internal: true` database network, and is not reachable by the frontend container.
- `postgres_data` and `runtime_secrets` form one recoverability unit: restoring the database without its matching secret volume requires an explicit database credential recovery procedure.
- The MVP rate limiter is local to a process. A shared/edge limiter is required when horizontally scaling.

## Evolution

Federated identity can be added behind the current-user dependency and external IdP groups can map to the existing access groups. Application ownership, requests, approvals, and comments can reference the existing owner labels and UUID identities. API credentials can gain application constraints without changing their external authentication mechanism. Additional resources/actions can extend the validated permission vocabulary without changing memberships. Notification and CI/CD-provider adapters should consume domain events while the policy evaluation contract remains stable.
