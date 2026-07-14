# Astra NDR — Repository Structure

```
astra-ndr/
├── AstraNdr.sln                 F# solution
├── Directory.Build.props        shared build settings (net8 server/shared, Fable client)
├── docker-compose.yml           full dev/demo stack
├── .env.example                 environment template (no real secrets)
├── .config/dotnet-tools.json    Fable 5 local tool manifest
│
├── src/
│   ├── Astra.Shared/            DOMAIN MODEL (shared by server & client)
│   │   ├── Primitives.fs        ids, severity, protocol, direction, lane enums
│   │   ├── Mitre.fs             ATT&CK tactic/technique + kill-chain types
│   │   ├── Events.fs            normalized event schema + typed payloads (DU)
│   │   ├── Sensors.fs           sensor, health, heartbeat types
│   │   ├── Entities.fs          entity profiles, groups, coverage config
│   │   ├── Detections.fs        detection + rule-definition types
│   │   ├── Scoring.fs           explainable score factors / breakdown
│   │   ├── Incidents.fs         incidents + investigation graph types
│   │   └── Api.fs               wire DTOs + route table (Routes module)
│   │
│   ├── Astra.Server/            CENTRAL BRAIN (Giraffe)
│   │   ├── Config.fs            environment-driven configuration
│   │   ├── Json.fs              single System.Text.Json policy (Fable-compatible)
│   │   ├── Classification.fs    CIDR internal/external, direction, lane
│   │   ├── Store.fs             thread-safe state + entity resolution
│   │   ├── DetectionEngine.fs   IDetectionRule + 6 starter rules + engine
│   │   ├── ScoringEngine.fs     explainable entity scoring
│   │   ├── Correlation.fs       detections → incidents, attack-profile classifier
│   │   ├── Assistant.fs         read-only evidence-bound AI provider (pluggable LLM)
│   │   ├── Graph.fs             investigation/attack graph engine (entity + incident)
│   │   ├── Hunt.fs              threat-hunting predicate engine + templates
│   │   ├── SeedData.fs          synthetic demo scenarios
│   │   ├── Ingestion.fs         DTO mapping + async pipeline + background worker
│   │   ├── Mappers.fs           domain → DTO projections
│   │   ├── HttpHandlers.fs      Giraffe routes/handlers
│   │   ├── Db.fs               forward-only migration runner (Npgsql)
│   │   └── Program.fs           host wiring, DI, startup, seed
│   │
│   ├── Astra.Sensor/            SENSOR AGENT (real Zeek/Suricata → brain)
│   │   ├── Zeek.fs              Zeek TSV parser (conn/dns/http/ssl/smb/dce_rpc/…)
│   │   ├── Suricata.fs          Suricata EVE JSON + fast.log parsers
│   │   ├── Agent.fs             batching HTTP agent, heartbeat, buffer, live-tail
│   │   └── Program.fs           CLI: replay / live modes
│   │
│   └── Astra.Client/            ANALYST CONSOLE (Fable 5 + Feliz)
│       ├── Types.fs             client view of DTOs + Route DU + hash parser
│       ├── Api.fs               typed fetch client + Thoth decoders
│       ├── Theme.fs             palette + severity/status/score colors
│       ├── Charts.fs            inline SVG charts (bars, trend line)
│       ├── Components.fs        panels, badges, stat tiles, tables, remote-data view
│       ├── Pages/               Dashboard, EntityQueue, EntityDetail, Detections,
│       │                        Incidents, Sensors, Placeholder (roadmap pages)
│       ├── App.fs               shell: sidebar nav + hash router
│       ├── Main.fs              React root
│       ├── index.html / vite.config.js / package.json / styles.css
│
├── db/migrations/               PostgreSQL schema (forward-only)
│   └── 0001_core_schema.sql     40+ tables: sensors, events, entities, detections,
│                                incidents, rules, triage, threat intel, response,
│                                users/roles, audit, settings
│
├── deploy/
│   ├── server.Dockerfile        multi-stage F# publish (net10 build → aspnet runtime)
│   ├── client.Dockerfile        Fable→Vite build → nginx
│   └── nginx.conf               SPA + /api reverse proxy + hardening headers
│
├── tests/Astra.Tests/           xUnit: parser, detection, scoring, entity-resolution tests
│
├── lab/
│   ├── demo_sensor.py           sensor simulator: attack scenarios over the ingest API
│   ├── generate_samples.py      writes sample Zeek/Suricata logs for sensor replay
│   └── samples/                 generated Zeek TSV + Suricata eve.json
│
└── docs/                        architecture, schema, detection, scoring, API,
                                 security, entity resolution, mitre, lab, roadmap, …
```

## Project references

```
Astra.Shared  ← Astra.Server   (server references the domain)
Astra.Shared  ← Astra.Client   (client references the same domain; Fable compiles it to JS)
```

The shared project is the contract. Changing a DTO shape updates both sides at compile
time — no drift between backend responses and frontend decoders.
