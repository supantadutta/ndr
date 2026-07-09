# Astra NDR — Deployment & Delivery Roadmap

Astra is built in **small runnable phases while preserving the enterprise
architecture** — every phase ends with something that compiles and runs.

## Phase 1 — Full-stack skeleton  ✅ delivered

- F# solution: shared domain model, Giraffe backend, Fable 5 console
- Normalized event schema + typed payloads; CIDR classification; entity resolution
- Async ingestion pipeline (bounded channel, backpressure, background worker)
- Detection engine (6 explained starter rules) + explainable scoring + correlation
- PostgreSQL migrations (40+ tables) applied at startup; in-memory fallback
- Sensor heartbeat/health + auto-registration
- Dashboard, entity queue/detail, detection center, incidents, sensor health
- Docker Compose (postgres + redis + clickhouse + server + client) + lab sensor

## Phase 2 — Ingestion & sensors

- Zeek log parser; Suricata EVE JSON + fast-log parsers
- Normalization pipeline from raw logs; PCAP replay mode
- Telemetry persistence to ClickHouse; time partitioning; hot/warm/cold retention
- Redis-backed queues; batch writes; dead-letter queue; deduplication
- Secure sensor enrollment; config sync; deeper sensor health UI

## Phase 3 — Detection & triage depth

- Full detection families (A–H) and the behavioral **baseline engine** (EMA, z-score,
  MAD, percentiles, rarity, time-of-day/day-of-week, decay)
- Risk scoring refinements; triage workflows (close/allowlist/suppress/assign/escalate)
- Triage filters + allowlists with audit
- Detection engineering UI (enable/disable, threshold tuning, test-against-samples,
  signature ruleset management)

## Phase 4 — Investigation

- Attack graph engine + views (radial, flow tree, blast radius, C2 infrastructure)
- Richer incident correlation and campaign stitching
- Historical metadata search + threat hunting (query builder, saved searches,
  scheduled hunts, pivots, convert-to-detection)

## Phase 5 — Intel, response & AI

- Threat intelligence (IOC/feed management, CSV/STIX-style import, match history)
- Response center + connectors (SIEM/SOAR/EDR/firewall) — approval-gated, simulation
  first, real connectors later
- Exports: Syslog/TLS, Kafka, Elastic/OpenSearch, Splunk-HEC-style, webhook
- Read-only **AI SOC assistant** (see `ai-assistant-security.md`) + reporting

## Beyond — Kubernetes & scale

- Ingestion channel → Kafka topic + consumer group; detection state partitioned by
  entity
- Stateless API replicas; materialized dashboard aggregates; query pagination
- Helm charts / K8s manifests; horizontal autoscaling; multi-tenancy
