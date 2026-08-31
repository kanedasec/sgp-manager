# SGP Manager instructions for agents

## Repository role

SGP Manager is both a deployed application and the policy authority used by
application CI pipelines. It manages applications, security gates, owner-scoped
bypass policies, machine credentials, and audit history. Its enforcement API
returns the blocking severities that `platform-workflows` applies to Semgrep,
Gitleaks, and Trivy findings.

This creates two simultaneous trust boundaries:

1. normal application security for the administrative portal and database;
2. CI/CD authorization security, because an incorrect policy response can
   permit or block deployments across other repositories.

Treat evaluation semantics, credential handling, migrations, and audit data as
security-sensitive code.

## Runtime architecture

```text
Browser / pipeline
  -> Caddy HTTPS
  -> unprivileged frontend nginx :8080
       |-> React SPA
       `-> /api, /docs, health, readiness, metrics proxy
            -> unprivileged FastAPI :8000
                 -> PostgreSQL :5432 on internal Docker network
```

Production images are built by GitHub Actions and published as:

```text
ghcr.io/kanedasec/sgp-manager-backend:sha-<full-commit>
ghcr.io/kanedasec/sgp-manager-frontend:sha-<full-commit>
```

The VPS runtime definition lives at `/opt/infra/sgp-manager/compose.yaml`, not
in this public source repository. The repository `docker-compose.yml` is for
local development and bootstrap behavior; production must not build from
`/opt/apps/sgp-manager` or publish arbitrary host ports.

## CI/CD path

```text
feature branch -> pull request
  |-> backend tests + frontend build + workflow validation
  `-> SGP pipeline preflight -> selected differential scanners -> currently deployed SGP Manager gate
protected merge -> main
  -> repeat CI
  -> publish backend and frontend with one sha tag
  -> ephemeral Tailscale tag:github-deploy
  -> restricted SSH as deployer
  -> sudo /usr/local/sbin/deploy-sgp-manager <sha-tag>
  -> Compose pull/up/migrations/health
  -> public HTTPS smoke tests
```

Do not split publish and deployment into independent workflows. The current
`standard-ci -> containers -> deploy` dependency chain provides ordering.

## Circular policy dependency

Pull requests in this repository are evaluated by the currently deployed SGP
Manager. Therefore changes to the enforcement API, authentication contract,
gate slugs, or response schema require a backward-compatible phased rollout.

Safe sequence:

1. deploy a server version that supports both old and new consumers;
2. update and validate `platform-workflows` against that compatible server;
3. migrate application callers to the new immutable platform revision;
4. remove old compatibility only after no pinned consumer depends on it.

Never make this repository's CI require a new SGP contract before a compatible
server is deployed. Do not bypass the policy check to resolve that cycle.

## Fail-closed enforcement invariants

`POST /api/v1/policies/resolve-pipeline` is the pre-scan contract. It resolves
the exact active gate policy assigned to the requested application and returns
only that policy's active gates in unique contiguous order. Unknown/inactive
applications return `404`; a missing, inactive, empty, malformed, or
inactive-gate policy returns `503`. The pipeline API credential must remain
isolated to preflight and policy jobs and must never be exposed to scanner jobs.

`POST /api/v1/policies/evaluate-enforcement` is the authoritative pipeline
contract. Preserve all of these behaviors:

- for a known application, begin with each selected policy gate's blocking severities;
- treat an empty or malformed stored policy severity set as all canonical severities;
- for an unknown application, retain the active gate catalog defaults as fail-closed behavior;
- remove only severities covered by an effective bypass for the exact active
  application and gate;
- return unchanged defaults for unknown or inactive applications;
- return `404` for an explicitly requested unknown/inactive gate;
- return only canonical ordered severities: low, medium, high, critical;
- use timezone-aware UTC timestamps;
- expose no justification, user, credential, owner, or audit data;
- let every authentication, validation, rate-limit, and server error remain a
  non-success that consumers interpret as block/no bypass.

The older `/evaluate` endpoint returns active bypass entries and must not be
confused with final enforcement calculation.

## Policy and authorization invariants

- Bypass effectiveness uses the half-open window
  `valid_from <= now < expires_at`.
- Revoked policies and scopes are never effective and are never physically
  deleted through the administrative API.
- PostgreSQL exclusion constraints are the final defense against overlapping
  non-revoked `(application, gate)` windows; service validation alone is not
  sufficient under concurrency.
- A multi-gate bypass policy may contain only gates belonging to the same owner
  as the bypass policy. This prevents crossing owner authorization boundaries.
- A reusable gate policy owns the selected gate order and per-gate blocking
  severities. Each application has exactly one assigned policy; many
  applications may share one policy.
- `ADMIN` is the management/break-glass role. Normal users receive only the
  union of explicit permissions from active groups.
- Direct-object endpoints must independently enforce the same owner permission
  as filtered list endpoints.
- Application mutation, access management, API credentials, dashboards, and
  audit logs remain administrator-only unless an explicit authorization design
  is reviewed.
- Reusable gate-policy creation, editing, activation, and application assignment
  remain administrator-only. Owner-scoped gate permissions do not authorize
  changing standards that can affect applications outside that owner boundary.
- An in-use active gate policy cannot be deactivated, and a gate referenced by
  an active gate policy cannot be renamed or deactivated until it is removed.
- Administrative writes and their audit events belong in the same transaction
  where applicable. Audit metadata must remain allow-limited and scrubbed.

## Credential and session invariants

- Pipeline credentials arrive only in `X-API-Key`, require `policy:read`, may
  expire or be revoked, and are stored only as a peppered HMAC digest.
- The raw API key is returned once at creation. Never persist or log it.
- The API-key pepper, JWT key, PostgreSQL password, initial administrator
  password, Tailscale secrets, and SSH private keys must never enter Git,
  images, artifacts, exception messages, or audit metadata.
- Administrative APIs require a Bearer JWT and re-read the active user.
- The documentation cookie is HttpOnly and SameSite=Strict and authorizes only
  `/docs`, `/redoc`, and `/openapi.json`; it must not authorize admin APIs.
- `SESSION_COOKIE_SECURE=true` is required behind production HTTPS.
- A bootstrapped administrator marked `must_change_password` may access only
  the identity/password-change flow until the password is changed.
- Sensitive Pydantic inputs must stay hidden in validation errors, and request
  bodies/credentials must never be written to structured logs.

## Database and migration rules

Alembic is the only production schema-management mechanism. The backend image
runs `alembic upgrade head` before starting Uvicorn.

When changing persistence:

1. add a new migration; never edit a migration already deployed;
2. make upgrades safe for existing production rows and deterministic under
   PostgreSQL;
3. preserve UUID identities, timezone-aware timestamps, uniqueness, foreign
   keys, and exclusion constraints;
4. include explicit data migration for new required fields;
5. ensure old application code and the migration ordering cannot create an
   unsafe mixed state during rollout;
6. update model, schema, service/repository, API, and tests together;
7. test upgrade behavior against PostgreSQL when using database-specific
   constraints—SQLite unit tests are not sufficient evidence.

Tests may use `Base.metadata.create_all()` only for isolated SQLite fixtures.
Do not introduce it as a production migration fallback.

`postgres_data` and generated runtime secrets are one recoverability unit. A
database backup without the matching secrets requires deliberate credential
recovery and may invalidate stored API-key digests or sessions.

## Secrets bootstrap

`docker/initialize-secrets.sh` is a one-shot, network-disabled initializer. It
creates missing files with a restrictive umask and never overwrites an existing
non-empty secret. Preserve idempotency, lack of network access, atomic writes,
and the rule that values are never logged.

Do not add secrets to `docker-compose.yml`. Local overrides may supply initial
values through private environment files, but production state belongs under
`/opt/data/sgp-manager` and root-controlled `/opt/infra/sgp-manager` files.

## Code ownership map

- `backend/app/api/`: HTTP routing and dependency enforcement.
- `backend/app/schemas/`: validated external contracts.
- `backend/app/models/`: SQLAlchemy persistence entities.
- `backend/app/repositories/`: reusable policy queries.
- `backend/app/services/`: domain operations, authorization, audit, bootstrap.
- `backend/app/core/`: settings, database, logging, cryptography/security.
- `backend/migrations/`: ordered production schema history.
- `frontend/src/`: React portal and API client.
- `frontend/nginx.conf`: SPA serving, backend proxying, and browser headers.
- `.github/workflows/`: small callers pinned to reviewed platform commits.

Keep HTTP handlers thin. Put reusable domain behavior in services/repositories
and validate all external input/output with schemas. Avoid premature service
splitting; the current transaction boundary is a deliberate modular monolith.

## Health, ingress, and observability

- `/health` is process liveness.
- `/ready` verifies database connectivity and is the deployment readiness path.
- `/metrics` is operational data and Caddy blocks it from public access.
- Caddy is the only public ingress. Backend, PostgreSQL, and frontend publish no
  production host ports.
- PostgreSQL remains only on the internal database network.
- Backend and frontend continue to run unprivileged with health checks.
- Logs use request IDs and route-aware metrics without recording bodies or
  credentials.

Do not expose administrative APIs, documentation, metrics, or database ports
through a new public route without a specific reviewed requirement.

## Required development workflow

1. Update local `main` and create a feature branch.
2. Make the smallest coherent backend/frontend/migration change.
3. Add tests for success, denial, malformed input, and authorization boundaries
   relevant to the change.
4. Run backend tests and the frontend production build locally.
5. Validate workflows and scan for accidental secrets.
6. Open a pull request and pass Standard CI, Semgrep, Gitleaks, Trivy, and the
   SGP Manager policy gate.
7. Merge through protected `main`; do not bypass required checks.
8. Verify both GHCR images share the merge SHA and the deployment job succeeds.
9. Confirm `/ready`, public HTTPS, migrations, and the deployed image revision.

## Required local validation

Backend:

```bash
cd backend
python3 -m pytest -q tests
```

Frontend:

```bash
cd frontend
npm ci --no-audit --no-fund
npm run build
```

Workflow and repository hygiene from the root:

```bash
actionlint .github/workflows/*.yaml
git diff --check
if git grep -n -E '__[A-Z0-9_]+__' -- . ':(exclude)AGENTS.md'; then
  echo 'Unresolved template placeholder found' >&2
  exit 1
fi
```

Use only test credentials in fixtures. Run Gitleaks with the central
`platform-workflows` configuration before pushing and never print secret
values from a finding.

## Deployment boundaries

Application source is not built on the VPS. Production deployment accepts only
an immutable `sha-<40 lowercase hex>` tag, pulls both images, verifies their OCI
revision labels, updates deployment state atomically, runs Compose without
build, waits for backend/frontend health, and rolls back the previous tag on
failure.

Human administration uses Tailscale SSH as `kanedasec` plus `sudo`. CI uses the
separate `deployer` identity, a forced SSH dispatcher, and sudo permission for
only `/usr/local/sbin/deploy-sgp-manager`. Never add `deployer` to `docker` or
grant it unrestricted sudo.

## Handoff requirements

Report tests and builds run, migration impact, API compatibility, gate-policy
impact, security findings, image SHA/digests, and deployment verification. Do
not claim completion when only unit tests pass if the change affects PostgreSQL
constraints, policy evaluation, credentials, migrations, or the deployed CI
contract.
