# Pipeline API

## Resolve final gate enforcement

```http
POST /api/v1/policies/evaluate-enforcement
Content-Type: application/json
X-API-Key: sec_...
```

Request:

```json
{
  "application": "payment-api",
  "gate": "secrets"
}
```

`gate` is optional. When omitted, all active gates are returned.

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

The server computes each entry using:

```text
blocking severities = gate default blocking severities - effective bypass severities
```

Only active, non-revoked bypasses within `valid_from <= generated_at < expires_at` can remove a severity. Bypasses attached to inactive gates have no effect. An unknown or inactive application receives the complete defaults with nothing removed. This makes inventory mistakes fail closed.

Pipeline consumers should block a finding only when its normalized severity is an exact member of `blocking_severities`. A missing/invalid response, unknown requested gate (`404`), authentication error, or interpretation error must be treated as **BLOCK / NO BYPASS**.

## Evaluate policies

```http
POST /api/v1/policies/evaluate
Content-Type: application/json
X-API-Key: sec_...
```

Request:

```json
{
  "application": "payment-api",
  "gate": "secrets"
}
```

`application` is required. `gate` is optional. Both are exact lowercase slugs containing letters, digits, and single hyphens. Credentials never belong in the URL or query string.

Successful response:

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

The server returns only policies that are effective at `generated_at`, non-revoked, and attached to an active application and active gate. Justification, users, UUIDs, and audit data are intentionally excluded.

An administrator may approve several gate scopes together as one policy. Evaluation deliberately flattens that group into one minimal response entry per gate, so pipeline consumers do not need to understand administrative grouping.

Administrative owner labels and human group roles do not alter this machine contract. They control who may manage gates and policies in the portal; the evaluation service still derives a deterministic result exclusively from active gates and effective, non-revoked policies.

An existing application without a bypass, an unknown application, and an inactive application all safely produce:

```json
{
  "application": "payment-api",
  "generated_at": "2026-08-26T21:30:00Z",
  "policies": []
}
```

This means **NO BYPASS**.

## Consumer algorithm

For each finding, find the response entry with the exact gate slug. Bypass only when the finding severity is an exact member of `bypass_severities` and the current time is still before `expires_at`. Block otherwise.

```text
response unavailable or malformed -> NO BYPASS
no policy for exact gate          -> NO BYPASS
severity absent from array        -> NO BYPASS
current time >= expires_at        -> NO BYPASS
otherwise                         -> BYPASS this severity only
```

Do not cache beyond `expires_at`; short-lived caching also delays revocation and is discouraged for the MVP.

## Errors

- `401`: key missing, unknown, revoked, or expired.
- `403`: credential lacks `policy:read`.
- `422`: malformed request.
- `429`: rate limit exceeded.
- `500`: unexpected server error; response includes a correlation ID.

All non-2xx responses are **NO BYPASS**. Pipelines may stop entirely when the manager is unavailable, which is stricter and recommended for high-assurance environments.

## Example shell integration

```bash
set -eu
response_file="$(mktemp)"
trap 'rm -f "$response_file"' EXIT

curl --fail --silent --show-error \
  -X POST "${BYPASS_MANAGER_URL}/api/v1/policies/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${BYPASS_API_KEY}" \
  --data '{"application":"payment-api","gate":"secrets"}' \
  > "$response_file"
```

Keep the API key in the CI/CD platform's masked secret store. Never print the command with shell tracing enabled and never log the response together with authentication headers.
