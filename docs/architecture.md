# Astra NDR — Architecture

Astra NDR is a distributed detection-and-response platform: many collectors feed a
central analysis brain, which normalizes, enriches, detects, scores, correlates, and
exposes everything through typed APIs to a Fable 5 analyst console.

## Components

### Distributed collection tier
- **Network sensors** — SPAN/TAP/mirror ingestion, Zeek log collection, Suricata
  EVE/fast-log collection, flow metadata, packet statistics, protocol metadata. Each
  sensor reports heartbeat + health (CPU/RAM/disk/interface, packet drop, EPS), buffers
  locally when the brain is unreachable, and carries identity + API token, zone/group
  tags, and a version.
- **Cloud collectors** — cloud traffic-mirroring and audit-log ingestion (design).
- **Identity collectors** — authentication events (AD/Kerberos/NTLM, cloud SSO).
- **SaaS collectors** — SaaS audit logs (M365/GSuite-style).
- **PCAP replay** — offline analysis / lab mode.

### Central brain (`Astra.Server`)
A Giraffe application hosting:
1. **Ingestion API** — token-authenticated event batches + heartbeats.
2. **Ingestion pipeline** — a bounded channel with backpressure; a background worker
   drains it, classifies traffic, resolves entities, and runs the analysis cycle.
3. **Classification** — CIDR-based internal/external + traffic direction & lane.
4. **Entity resolution** — find-or-create canonical entities (host/account/domain/…).
5. **Detection engine** — modular rules (rule/statistical/behavioral/correlation/…)
   producing fully-explained detections.
6. **Scoring engine** — explainable risk/urgency/threat/certainty with signed factors.
7. **Correlation engine** — clusters detections into incidents; classifies attack
   profile; computes blast radius and containment guidance.
8. **Read APIs** — dashboard, entity queue/detail, detections, incidents, sensors.

### Storage tiers
- **PostgreSQL** — relational state: entities, detections, incidents, rules, triage,
  threat intel, response, users/roles, settings, audit. Migrations applied at startup.
- **ClickHouse / OpenSearch** — high-volume normalized telemetry (Phase 2+).
- **Redis** — cache + queues (Phase 2+).
- **Kafka-compatible design** — the ingestion channel abstraction maps cleanly onto a
  Kafka topic + consumer group for horizontal scale later.

### Analyst console (`Astra.Client`)
A Fable 5 + Feliz single-page app. Hash-routed, dark SOC theme, inline SVG charts (no
external chart dependency, CSP-friendly). Talks to the brain over REST/JSON using
Thoth.Json decoders that mirror the shared DTOs exactly.

## Data flow (one event's life)

```
sensor → POST /api/ingest/events (X-Astra-Sensor-Token)
       → Mapping.fromDto      (DTO → typed NormalizedEvent + payload)
       → Classifier           (direction, lane, drop/exclude)
       → entity resolution    (source host created/updated)
       → bounded channel      (backpressure; DropOldest under overload)
worker → DrainOnce            (channel → in-memory + Postgres window)
       → DetectionEngine.Run  (rules over sliding window → Detection[])
       → ScoringEngine        (recompute explainable entity scores)
       → Correlation          (cluster → Incident[])
console← GET /api/dashboard/summary, /api/entities/queue, /api/detections, …
```

## Design principles

- **Clean architecture** — domain (`Astra.Shared`) has no infra dependencies; the
  server depends on the domain; the client depends on the domain's wire DTO shapes.
- **Provider interfaces for external integrations** — response connectors, storage,
  and feeds are modeled behind types so real connectors slot in without touching core
  logic.
- **Fail-safe pipeline** — a rule that throws is isolated and never takes the pipeline
  down; the brain runs in-memory if Postgres is unavailable.
- **Explainability first** — every score and detection carries its evidence and its
  reasoning, because analyst trust depends on it.
- **Security by default** — sensor tokens, no automatic destructive response, untrusted
  external content treated as data, secrets only via environment.

## Scale path (Kubernetes-ready later)

- Ingestion channel → Kafka topic; the worker becomes a horizontally-scaled consumer
  group. Detection state partitions by entity.
- Postgres for state; ClickHouse for telemetry with time partitioning + hot/warm/cold
  retention.
- Stateless API replicas behind a load balancer; Redis for shared cache/rate-limiting.
- Materialized dashboard aggregates + query pagination for high event volume.
