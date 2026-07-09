# Astra NDR — Security Model

Astra is a security product; it holds itself to the standard it enforces.

## Authentication & authorization
- **Sensor ingestion** is gated by a shared token (`X-Astra-Sensor-Token`). Tokens are
  stored hashed (`sensors.api_token_hash`), never in plaintext.
- **RBAC** roles (`admin`, `analyst`, `readonly`, `sensor`) are seeded in migration
  0001 with a permission model. API authorization checks + session/API-key auth are
  wired in Phase 5; the schema (`users`, `roles`, `api_keys`) is present now.
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
