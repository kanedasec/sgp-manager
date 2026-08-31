# Security Gate Policy Manager

Repository-specific architecture, security invariants, and implementation rules
for coding agents are documented in [`AGENTS.md`](AGENTS.md).

Security Gate Policy Manager is a modular monolith for defining gate enforcement defaults and issuing, auditing, evaluating, and revoking temporary CI/CD security exceptions. The administrative portal runs on React, the versioned API on FastAPI, and persistent state on PostgreSQL.

The central rule is **fail closed**: an absent, unknown, expired, revoked, inactive, malformed, or unauthenticated policy never grants a bypass.

## Architecture

```text
Administrator -> React portal -> reusable gate policies -> application assignment -> PostgreSQL
Pipeline ------ X-API-Key ---> resolve-pipeline -> selected scanners
Pipeline ------ X-API-Key ---> evaluate-enforcement -> PASS / BLOCK
```

- `frontend`: React + TypeScript + Vite, served by unprivileged nginx.
- `backend`: FastAPI, Pydantic, SQLAlchemy, Alembic, Argon2 and JWT.
- `postgres`: durable domain and append-only audit records.
- Admin identity uses short-lived bearer JWTs. Pipeline identity uses opaque `sec_...` keys.
- API keys are shown once and stored only as HMAC-SHA-256 digests using a server-side pepper.
- One application-level bypass policy can contain multiple gate scopes. Every scope stores its own validated JSON severity array (`low`, `medium`, `high`, `critical`) while sharing validity, justification, creator, and revocation history.
- Gates and policies have a required reusable owner label (for example `appsec`, `architecture`, or `quality`). All gates grouped into one policy must belong to that policy's owner.
- Human authorization is owner-scoped group RBAC. `ADMIN` users have implicit global access; `USER` accounts receive additive `view`, `create`, and `edit` roles from active groups.
- Every gate defines authoring defaults. Each reusable gate policy owns its ordered active scans and independent blocking severities. Effective enforcement is `assigned policy severities - currently active bypass severities`.
- Administrators create standards such as `crown-jewels`, assign one to each application, and compose each standard by dragging gates in the portal. Pipeline preflight resolves the application assignment before any scanner starts.
- `status` is calculated from UTC timestamps and revocation fields. A future policy is shown as `SCHEDULED`; effective states remain `ACTIVE`, `EXPIRED`, and `REVOKED`.

More detail is in [docs/architecture.md](docs/architecture.md).

## Quick start

Requirements: Docker Engine with Docker Compose v2.

From a clean checkout, no `.env` file or manual database initialization is required:

```bash
git clone <repository-url>
cd secpipe
docker compose up -d --build
docker compose ps
```

On the first run, `secrets-init` generates independent random PostgreSQL, JWT-signing, and API-key-pepper values. They are persisted in the private `runtime_secrets` named volume, mounted read-only by the services that consume them, and never printed. Subsequent starts reuse the same values.

`.env.example` is now optional and exists only for deployments that need to override names, ports, or first-run values. You may also supply overrides through the server/orchestrator environment without creating an `.env` file.

Open:

- Portal: <http://localhost:3000>
- OpenAPI: <http://localhost:3000/docs> (requires an active portal login and completed password change)
- Liveness: <http://localhost:3000/health>
- Readiness: <http://localhost:3000/ready>
- Metrics: <http://localhost:3000/metrics>

Only the frontend/nginx port is published. PostgreSQL has no host port and is attached only to the isolated internal `database` network. The frontend is not a member of that network; only the backend can reach PostgreSQL.

Alembic migrations run automatically before the API starts. PostgreSQL data is retained in `postgres_data`; generated service secrets are retained in `runtime_secrets`. Back up and restore these volumes together. Never remove only `runtime_secrets` while retaining an initialized PostgreSQL volume, because a newly generated database password would no longer match the existing database role.

Useful lifecycle commands:

```bash
# Stop while preserving database data and generated secrets
docker compose down

# Start again using the existing volumes
docker compose up -d

# Follow application logs
docker compose logs -f backend frontend
```

To deliberately reset the installation from zero, including all database records, API credentials and generated secrets:

```bash
docker compose down --volumes --remove-orphans --rmi local
docker compose up -d --build
```

The reset command is irreversible unless the named volumes were backed up.

### Upgrading an existing installation

An installation that already has `postgres_data` should perform the first upgraded start with its existing `POSTGRES_PASSWORD`, `JWT_SECRET`, and `API_KEY_PEPPER` environment values still available. `secrets-init` copies them into `runtime_secrets` exactly once. After that successful start and login verification, the old `.env` file can be removed; normal restarts use the persisted files.

## Initial administrator

When no user exists and no overrides are provided, the bootstrap login is:

```text
Username: admin
Password: ChangeMeNow!2026
```

This credential is deliberately restricted to first-run enrollment. A successful login with it is redirected to `/change-password`; all administrative APIs and `/docs` return an authorization error until a different password of at least 12 characters is saved. The documentation cookie is not issued before this change. The default password stops working immediately after replacement and bootstrap never overwrites an existing user.

Because the bootstrap credential is public knowledge, perform the first login before exposing the portal to an untrusted network. A server-specific initial value can be supplied without an `.env` file:

```bash
INITIAL_ADMIN_PASSWORD='a-server-specific-bootstrap-password' docker compose up -d --build
```

It is still mandatory to replace that value in the portal. The initial password is Argon2-hashed before persistence and never printed.

Optional Compose overrides include:

```bash
FRONTEND_PORT=8443 \
INITIAL_ADMIN_USERNAME=security-admin \
INITIAL_ADMIN_EMAIL=security-admin@example.com \
docker compose up -d --build
```

nginx routes the portal and proxies API traffic to FastAPI over the private Compose network, so browser and pipeline clients use the same origin. Swagger UI, ReDoc, and `/openapi.json` require the HttpOnly documentation session. Administrative API mutations still require the Bearer JWT. Set `SESSION_COOKIE_SECURE=true` whenever HTTPS is used.

## Production deployment

For an internal company server:

1. Place the published frontend port behind an HTTPS reverse proxy or ingress.
2. Set `SESSION_COOKIE_SECURE=true` and restrict `CORS_ORIGINS` to the final HTTPS origin.
3. Complete the bootstrap password change before opening network access to other users.
4. Back up `postgres_data` and `runtime_secrets` together.
5. Store pipeline API keys only in the CI/CD platform's masked secret store.
6. Restrict `/metrics` at the ingress if the portal is reachable from an untrusted network.

Example without an `.env` file:

```bash
FRONTEND_PORT=3000 \
CORS_ORIGINS=https://policy-manager.company.example \
SESSION_COOKIE_SECURE=true \
INITIAL_ADMIN_PASSWORD='a-unique-bootstrap-password' \
docker compose up -d --build
```

The only published container port is nginx. Do not add a PostgreSQL `ports:` mapping: the provided Compose file intentionally attaches PostgreSQL only to the internal `database` network.

## Pipeline integration

Create an API credential in **Access Management → API Credentials** and copy it immediately. The full value is not recoverable.

First resolve the ordered security pipe. The workflow must stop on every error,
an empty response, or an unknown gate implementation:

```bash
curl --fail-with-body -X POST \
  http://localhost:3000/api/v1/policies/resolve-pipeline \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${BYPASS_API_KEY}" \
  -d '{"application":"payment-api"}'
```

The recommended endpoint returns the final severities that must block each gate after applying any currently effective bypass:

```bash
curl --fail-with-body -X POST \
  http://localhost:3000/api/v1/policies/evaluate-enforcement \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${BYPASS_API_KEY}" \
  -d '{
    "application": "payment-api",
    "gate": "secrets"
  }'
```

```json
{
  "application": "payment-api",
  "generated_at": "2026-08-26T21:30:00Z",
  "gates": [
    {
      "gate": "secrets",
      "blocking_severities": ["critical"]
    }
  ]
}
```

For example, if `secrets` blocks `medium`, `high`, and `critical` by default while an active bypass authorizes `medium` and `high`, only `critical` remains blocking. Unknown or inactive applications receive the complete gate defaults with no bypass reduction. An unknown requested gate returns `404`; consumers must treat every non-2xx or malformed response as **BLOCK / NO BYPASS**.

The original bypass-inspection endpoint remains available for compatible consumers:

```bash
curl --fail-with-body -X POST \
  http://localhost:3000/api/v1/policies/evaluate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${BYPASS_API_KEY}" \
  -d '{
    "application": "payment-api",
    "gate": "secrets"
  }'
```

Example response:

```json
{
  "application": "payment-api",
  "generated_at": "2026-08-26T21:30:00Z",
  "policies": [
    {
      "gate": "secrets",
      "bypass_severities": ["low", "medium", "high"],
      "expires_at": "2026-09-25T21:30:00Z"
    }
  ]
}
```

Omit `gate` to retrieve all effective gate policies for the application. A successful empty response means **NO BYPASS**. An unknown application deliberately returns an empty list to remain deterministic and avoid disclosing inventory. Authentication and transport failures must also be handled by the consumer as **NO BYPASS**; never reuse a stale response after its `expires_at`.

See [docs/api.md](docs/api.md) for the exact consumer contract.

## Administrative workflow

1. Sign in at `/login`.
2. Under **Access Management → Owners**, create ownership labels such as AppSec, Architecture, and Quality.
3. Register one or more security gates, assigning an owner and selecting at least one policy-authoring default severity per gate.
4. As an administrator, create a reusable gate policy, drag active gates into its non-empty ordered pipe, and configure blocking severities for every selected gate.
5. Register an application using its exact CI repository slug and assign one active gate policy. Create temporary bypass policies separately when a reviewed exception is needed.
6. Generate a pipeline API credential and store it in the CI/CD secret store.
7. Resolve the pipe using `POST /api/v1/policies/resolve-pipeline`, then resolve final blocking severities using `POST /api/v1/policies/evaluate-enforcement`.
8. Revoke the bypass when it is no longer required and inspect the audit log.

Portal users, groups, owners, and API credentials are managed together under **Access Management**. Administrators cannot deactivate or downgrade themselves, passwords are never returned, and every access-management change is audited.

### Owner-scoped roles

Group roles use the form `<action>-<resource>:<owner>`:

```text
view-policies:all
create-policies:appsec
edit-policies:appsec
view-gates:appsec
create-gates:architecture
edit-gates:quality
```

Supported actions are `view`, `create`, and `edit`; supported resources are `gates` and `policies`. The special `:all` scope covers every owner. Roles from all active groups assigned to a `USER` are combined. An `edit-policies` role also authorizes manual revocation because revocation is a policy state change. Access management, applications, API credentials, audit logs, and the dashboard remain administrator-only; authenticated standard users may read the application catalog needed to compose and inspect policies.

Policy ownership cannot be used to cross an authorization boundary: every gate selected in a multi-gate policy must have the same owner as the policy. Moving a gate or policy to another owner requires edit permission for both the existing and target owners.

No security-relevant entity has an HTTP `DELETE` operation. Applications and gates are disabled; policies and credentials are revoked.

## Policy concurrency

For the same application and gate, non-revoked half-open time windows `[valid_from, expires_at)` may not overlap. The service returns an explanatory `409`, while a PostgreSQL GiST exclusion constraint provides authoritative protection against races between API workers. A revoked record releases its time range for a replacement while remaining in history.

## Security considerations

- Passwords use Argon2id and API keys use peppered HMAC-SHA-256 digests.
- JWT and key-pepper secrets must contain at least 32 characters whether provided explicitly or loaded from the generated secret files.
- PostgreSQL, JWT, and key-pepper secrets are generated from kernel randomness and stored in a Compose volume when explicit overrides are absent; they are not hardcoded in the image or repository.
- The well-known bootstrap password cannot access domain APIs or documentation and must be replaced before portal enrollment completes.
- The pipeline endpoint exposes only gate, severities, and expiration; no justification or internal IDs.
- Inputs are bounded and validated; SQLAlchemy emits parameterized statements.
- Security headers, restrictive CORS, correlation IDs, JSON logs, generic 500 responses, and per-instance evaluation rate limiting are enabled.
- Logs and audit metadata exclude passwords, tokens, authorization headers, raw API keys, and key hashes.
- Owner checks are enforced by the backend on list, detail, create, update, and revoke operations; the portal's hidden controls are usability aids, not the authorization boundary.
- Application containers run as non-root users. PostgreSQL is not published to the host, belongs only to an internal database network, and is unreachable directly from the frontend network.
- `/metrics` is intentionally unauthenticated for scraping. Protect this route at an external ingress when port `3000` is reachable from an untrusted network.
- The in-memory rate limiter is appropriate for basic MVP abuse control. Deployments requiring a global limit across replicas should use an ingress or shared Redis-backed limiter.

## Development and tests

Backend:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements-dev.txt
PYTHONPATH=backend .venv/bin/pytest -q backend/tests
```

Frontend:

```bash
cd frontend
npm ci
npm run build
```

Migration validation against the Compose database:

```bash
docker compose exec backend alembic current
docker compose exec backend alembic check
```

## Repository hygiene

The repository includes a `.gitignore` for local environment files, private keys, virtual environments, dependency directories, build output, test databases, coverage files, logs and editor metadata. `.env.example`, migrations, lockfiles and the Docker secret-initialization script remain tracked.

Before the first push to GitHub, verify the staged files:

```bash
git init
git add .
git status
git diff --cached --check
```

Never force-add `.env`, private keys, local database files or generated runtime secrets. Docker named-volume content is outside the repository and should be backed up through an approved operational process rather than committed.

## Future extension points

The group/membership model, owner labels, credential scopes array, service/repository boundaries, versioned API, and UUID relationships leave space for OIDC/SAML federation, application-owner assignments, application-restricted credentials, request/approval workflows, comments, notifications, and provider-specific CI/CD integrations without splitting the MVP into microservices.
