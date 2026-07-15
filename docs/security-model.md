# Astra NDR — Security Model

Astra is a security product; it holds itself to the standard it enforces.

## Authentication & authorization
- **Sensor ingestion** is gated by a shared token (`X-Astra-Sensor-Token`). Tokens are
  stored hashed (`sensors.api_token_hash`), never in plaintext.
- **RBAC is enforced** when `ASTRA_AUTH_ENABLED=true` ([`Auth.fs`](../src/Astra.Server/Auth.fs)):
  every API route requires a session token (`Authorization: Bearer`, issued by
  `/api/auth/login`) or an API key (`X-Astra-Api-Key`), and asserts a permission —
  `read:api`, `triage:write`, `respond:request`, `respond:approve`, `admin:manage`.
  Default roles: `admin` (`*`), `analyst` (read/triage/request — **cannot approve**),
  `readonly`, `sensor`. With auth disabled (dev/demo) the guards are pass-throughs.
- **Passwords and API keys are stored only as PBKDF2-SHA256 hashes** (120k iterations,
  per-hash salt, constant-time compare). An API key's plaintext is returned exactly once
  at mint time. Login failures return a uniform 401 that does not reveal whether the
  user exists. A bootstrap admin is created at startup from `ASTRA_ADMIN_USER` /
  `ASTRA_ADMIN_PASSWORD`; the server warns loudly if the default password is unchanged.
- Sessions expire after `ASTRA_SESSION_TTL_HOURS` (default 12) and are evicted on use.
- **SSO-ready** — `users.sso_subject` supports external IdP subjects.

## Secrets
- All secrets come from **environment variables** (`ASTRA_POSTGRES`,
  `ASTRA_SENSOR_TOKEN`, DB passwords). `.env` is gitignored; `.env.example` documents
  the shape with placeholder values.
- Connector configs reference env keys rather than embedding secrets
  (`response_connectors.config`).
- Structured logging avoids emitting secrets; connection strings are never logged.

## Input handling
- Ingestion validates sensor id (GUID), token, and body shape; malformed batches are
  rejected with a 400 and never crash the pipeline.
- Request size limits, rate limiting, and safe file-upload / ruleset-upload validation
  are part of the ingestion + detection-engineering hardening (Phase 2–3).
- Output is JSON-encoded through a single serializer policy.

## Untrusted content isolation (critical for the AI assistant)
Logs, domains, URLs, file names, HTTP headers, user-agents, email content and alert
text are **attacker-controlled**. Astra treats them as **data, never instructions**:
- The AI SOC assistant is **read-only** and **evidence-bound**. It cannot execute
  response actions, modify triage filters, or suppress detections.
- It must separate fact / inference / recommendation, cite event ids, state
  uncertainty, and never invent evidence.
- Prompt construction isolates untrusted fields to defend against indirect prompt
  injection. See [`ai-assistant-security.md`](ai-assistant-security.md).

## No automatic destructive action
- **Every response action requires analyst approval**, is auditable, has a status, and
  supports simulation mode + rollback where possible.
- **Live delivery is doubly gated**: an action executes for real only when (1) a human
  with `respond:approve` approves it AND (2) an admin has explicitly flipped the matching
  connector out of simulation mode (`POST /api/response/connectors/{name}/mode`, audited).
  Otherwise the approval records a simulated result. The engine never enforces on its own.
- The AI assistant recommends; it never acts.

## Auditability
- `audit_logs` records actor, action, subject, and details for triage changes, response
  actions, and admin operations.
- Detections, incidents and score changes carry timestamps and change reasons.

## Fail-safe posture
- A failing detection rule is isolated and logged, not fatal.
- The brain runs in-memory if Postgres is unavailable, preserving visibility during a
  storage outage rather than dropping to zero.
- Ingestion sheds load (DropOldest) under overload rather than blocking sensors.

## Multi-tenancy readiness
Schema and entity model are designed so a tenant discriminator can be added without
reshaping core tables; classification and scoring are already per-environment.
