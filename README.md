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

## What works today (Phase 1)

- ✅ F# solution: shared model, Giraffe backend, Fable 5 console
- ✅ Normalized event schema + typed protocol payloads (DNS/HTTP/TLS/SMB/DCERPC/Auth/…)
- ✅ Internal/external CIDR classification + traffic direction/lane
- ✅ Entity resolution (IP→host, account, domain, external destination)
- ✅ Async ingestion pipeline (bounded channel, backpressure, background worker)
- ✅ Detection engine with 6 real starter rules across recon / C2 / lateral /
  credential / exfil families, each fully explained (evidence, baseline comparison,
  why-suspicious, investigation & response steps, MITRE mapping)
- ✅ Explainable scoring (risk / urgency / threat / certainty with signed factors)
- ✅ Correlation engine → incidents with attack-profile classification
- ✅ PostgreSQL migrations (40+ tables) applied at startup; in-memory fallback
- ✅ Sensor heartbeat + health, auto-registration
- ✅ Dashboard, Entity Queue, Entity Detail, Detection Center, Incidents, Sensor Health
- ✅ Docker Compose (postgres + redis + clickhouse + server + client)
- ✅ Lab sensor simulator exercising the HTTP ingest API

## Delivery roadmap

| Phase | Focus |
|-------|-------|
| **1 — done** | Full-stack skeleton, schema, ingestion + detection + scoring + correlation, first dashboards, Docker Compose, lab |
| **2** | Zeek parser, Suricata EVE/fast-log parsers, normalization from raw logs, PCAP replay, telemetry persistence (ClickHouse), sensor health UI depth |
| **3** | Full detection families, baseline engine, triage workflows, detection engineering UI |
| **4** | Attack graph, richer incident correlation, threat-hunting search, saved searches, custom detections |
| **5** | Threat intelligence, response center + connectors, SIEM/webhook/Kafka exports, AI investigation assistant, reporting |

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
