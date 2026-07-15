# Astra NDR

**Astra NDR** is an original, enterprise-grade **Network Detection, Investigation, and
Response** platform built in **F#** end-to-end — a Giraffe backend, a Fable 5 analyst
console, and a shared F# domain model used by both.

Astra provides enterprise-wide visibility, attacker-behavior detection, explainable
entity risk scoring, attack-path investigation, threat hunting, analyst triage, and
controlled (analyst-approved) response across hybrid environments.

> **Original work.** Astra NDR is inspired by the general capabilities of modern
> NDR/SOC platforms but copies no proprietary product, vendor name, UI, branding,
> private algorithm, or commercial implementation detail. MITRE ATT&CK® tactic and
> technique identifiers are public taxonomy references.

---

## Why F# across the stack

- **One domain model, zero drift.** `Astra.Shared` defines the normalized event
  schema, entities, detections, incidents and scoring types once. The backend and the
  Fable 5 frontend both compile against it.
- **Discriminated unions model the security domain naturally** — event categories,
  protocol payloads, MITRE tactics, kill-chain stages, attack profiles.
- **Pure, unit-testable detection and scoring logic**, wired into an async ingestion
  pipeline with backpressure.

## Architecture at a glance

```
 sensors / collectors                central brain (Astra.Server)              console
┌─────────────────────┐   HTTPS   ┌──────────────────────────────────┐   ┌──────────────┐
│ Zeek / Suricata     │  +token   │ ingest → classify → entity-resolve│   │ Fable 5 SPA  │
│ flow / pcap replay  │──────────▶│   → detection engine             │◀──│ (Feliz)      │
│ cloud / identity    │           │   → explainable scoring          │   │ REST/JSON    │
│ heartbeats/health   │           │   → correlation → incidents      │   └──────────────┘
└─────────────────────┘           │ Postgres · Redis · ClickHouse    │
                                  └──────────────────────────────────┘
```

Full detail in [`docs/architecture.md`](docs/architecture.md).

## Repository layout

```
src/
  Astra.Shared/     F# domain model + wire DTOs (shared by server & client)
  Astra.Server/     Giraffe API, ingestion pipeline, detection/scoring/correlation
  Astra.Client/     Fable 5 + Feliz analyst console (Vite)
db/migrations/      PostgreSQL schema (forward-only, applied at startup)
deploy/             Dockerfiles + nginx config
lab/                Demo sensor simulator (attack scenarios over the ingest API)
docs/               Architecture, schema, detection/scoring, API, security, roadmap
```

See [`docs/repository-structure.md`](docs/repository-structure.md).

## Quick start

### Option A — Docker Compose (full stack)

```bash
cp .env.example .env          # adjust secrets
docker compose up --build
# console: http://localhost:8080    API: http://localhost:5170
```

### Option B — local dev

Prerequisites: **.NET SDK 10** (Fable 5 tooling targets net10), **Node 18+**.

```bash
# 1) backend (seeds a demo environment on first run)
dotnet run --project src/Astra.Server
#    API on http://localhost:5170

# 2) frontend (Fable watch + Vite, proxies /api to the backend)
cd src/Astra.Client
npm install
dotnet tool restore
dotnet fable watch --run vite
#    console on http://localhost:5173
```

### Drive the lab sensor (optional)

```bash
python3 lab/demo_sensor.py --api http://localhost:5170 --token dev-sensor-token-change-me
```

This authenticates as a sensor and replays six attack scenarios (port scan, DNS
tunnel, HTTPS beaconing, brute-force + success, admin-share lateral movement, large
exfil) over the **real** ingestion API. Watch them surface as detections and
correlated incidents. See [`docs/lab-demo.md`](docs/lab-demo.md).

## What works today (Phases 1–2)

- ✅ F# solution: shared model, Giraffe backend, Fable 5 console, **real sensor agent**
- ✅ Normalized event schema + typed protocol payloads (DNS/HTTP/TLS/SMB/DCERPC/Auth/**IDS**/…)
- ✅ Internal/external CIDR classification + traffic direction/lane
- ✅ Entity resolution (IP→host, account, domain, external destination)
- ✅ Async ingestion pipeline (bounded channel, backpressure, background worker)
- ✅ **Astra.Sensor agent** — parses **real Zeek TSV + Suricata EVE JSON / fast.log**,
  normalizes, and posts over HTTP; live-tail and PCAP-replay modes; local buffering + retry
- ✅ Detection engine with **12 real rules** across recon / C2 / lateral / credential /
  exfil / policy / **signature (IDS)** families, each fully explained (evidence, baseline
  comparison, why-suspicious, investigation & response steps, MITRE mapping)
- ✅ **Behavioral baseline engine** — EMA, z-score, MAD, percentiles, robust z-score,
  frequency rarity, time-of-day histograms (streaming, pure, unit-tested)
- ✅ **Suricata IDS signatures correlated with behavioral detections** on the same entity
- ✅ Explainable scoring (risk / urgency / threat / certainty with signed factors)
- ✅ Correlation engine → incidents with attack-profile classification
- ✅ **Triage workflows**: close benign/remediated, mark expected, escalate, reopen —
  with score suppression, re-fire prevention, triage filters, allowlists, and a full audit trail
- ✅ **Detection engineering**: enable/disable and tune rule thresholds live (no rebuild)
- ✅ **AI investigation assistant** — read-only, evidence-bound, provider-pluggable
  (deterministic today; local/external LLM slots in via `IAnalysisProvider`)
- ✅ **Live auto-refreshing console** (8–10s polling) so real sensor telemetry streams in
- ✅ PostgreSQL migrations (40+ tables) applied at startup; in-memory fallback
- ✅ Sensor heartbeat + health, auto-registration
- ✅ Dashboard, Entity Queue, Entity Detail (+ AI summary), Detection Center (+ triage),
  Incidents, Sensor Health, Detection Engineering, Admin/Audit
- ✅ Docker Compose (postgres + redis + clickhouse + server + client + lab sensor)
- ✅ Lab: sample Zeek/Suricata log generator + sensor replay + HTTP ingest simulator
- ✅ **Test suite** (69 tests: parsers, detection rules, baselines, scoring, triage, entity resolution, graph/hunt, threat-intel + response, auth/RBAC, connectors, telemetry)

## Delivery roadmap

| Phase | Focus |
|-------|-------|
| **1 — done** | Full-stack skeleton, schema, ingestion + detection + scoring + correlation, first dashboards, Docker Compose, lab |
| **2 — done** | Real sensor agent (Zeek + Suricata EVE/fast-log parsers), normalization from raw logs, PCAP/log replay, IDS signature detection + correlation, live auto-refresh UI, AI investigation assistant (pluggable), test suite. *(ClickHouse telemetry persistence remains for Phase 2.5.)* |
| **3 — done** | Behavioral baseline engine (EMA/z-score/MAD/percentile/rarity/time-of-day), 12 detection rules across all families, tunable rule config (enable/disable + thresholds, live), triage workflows with suppression + audit trail, triage filters & allowlists, Detection Engineering + Admin/Audit UI. 37-test suite. |
| **4 — done** | Investigation/attack graph engine (radial graph around an entity or incident, shared-infrastructure blast-radius edges), threat-hunting metadata search with typed predicates + templates + top-talker aggregations, Attack Graph & Threat Hunting UI pages. 42-test suite. *(Saved searches / convert-to-detection persist in Phase 4.5.)* |
| **5 — done** | Threat-intelligence engine (IP/domain/URL/hash IOCs, feeds, CSV import, indicator-match detections with actor/campaign attribution), approval-gated **simulation-first** response actions (block/isolate/ticket/webhook/export) with connector registry, CEF/JSON SIEM exports, plaintext incident reporting, Threat Intelligence & Response Center UI pages. |
| **6 — done** | **Production hardening**: durable telemetry persistence (ClickHouse JSONEachRow / OpenSearch `_bulk` sinks, best-effort, never blocks ingestion), RBAC + session/API-key auth (PBKDF2, permission-gated routes, sign-in console gate, audited), and **live connector delivery** — approved actions execute for real (webhook/Splunk-HEC/syslog-CEF/REST) once an admin flips a connector out of simulation mode. 69-test suite. |

Details in [`docs/deployment-roadmap.md`](docs/deployment-roadmap.md).

## Documentation

Architecture · [repository structure](docs/repository-structure.md) ·
[installation](docs/installation.md) · [docker compose](docs/docker-compose.md) ·
[normalized schema](docs/normalized-schema.md) · [detection engine](docs/detection-engine.md) ·
[scoring engine](docs/scoring-engine.md) · [entity resolution](docs/entity-resolution.md) ·
[API reference](docs/api-reference.md) · [frontend guide](docs/frontend-guide.md) ·
[lab & demo](docs/lab-demo.md) · [security model](docs/security-model.md) ·
[MITRE mapping](docs/mitre-mapping.md) · [AI assistant security](docs/ai-assistant-security.md)

## License / usage

Original engineering project. Provided as-is for authorized security operations,
research, and educational use.
