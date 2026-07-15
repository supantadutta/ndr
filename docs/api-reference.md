# Astra NDR — API Reference

Base URL: the central brain (default `http://localhost:5170`). All responses are JSON
(camelCase). DTO shapes are defined once in
[`src/Astra.Shared/Api.fs`](../src/Astra.Shared/Api.fs) and the route table lives in
`Api.Routes`.

## Authentication

- **Read APIs** — open in Phase 1 dev; RBAC + session/API-key auth lands in Phase 5
  (schema already present: `users`, `roles`, `api_keys`).
- **Ingestion APIs** — require header `X-Astra-Sensor-Token: <token>` matching
  `ASTRA_SENSOR_TOKEN`.

## Read endpoints

### `GET /api/health`
Liveness. `{ "status": "ok", "service": "astra-ndr", "time": "…" }`

### `GET /api/dashboard/summary`
Returns `DashboardSummaryDto`: active incidents, open/critical detections, prioritized
entities, sensors online/total, events (24h), MITRE tactic distribution, detection trend
(12×1h buckets).

### `GET /api/entities/queue?page=1&pageSize=50`
Returns `EntityQueuePageDto` — entities with urgency > 0, ranked by urgency. Each item
has the four scores, detection/incident counts, criticality, group importance, triage
state.

### `GET /api/entities/{id}`
Returns `EntityDetailDto` — identity, scores, **score factors** (the explainable
ledger), recent detection ids, triage state. `404` if unknown.

### `GET /api/detections?page=1&pageSize=50`
Returns `DetectionPageDto`, ordered by threat score. List items include MITRE mapping,
severity/confidence, affected entity.

### `GET /api/detections/{id}`
Returns `DetectionDetailDto` — full evidence, event ids, why-suspicious, false-positive
considerations, recommended investigation & response steps. `404` if unknown.

### `GET /api/incidents`
Returns `IncidentListItemDto[]`, ordered by urgency — attack profile, primary entity,
detection count, blast radius, severity, status.

### `GET /api/sensors/health`
Returns `SensorHealthDto[]` — per-sensor status, version, mode, last heartbeat,
CPU/RAM/disk, packet drop, EPS, Zeek/Suricata/interface state, errors.

## Ingestion endpoints (sensor → brain)

### `POST /api/ingest/events`
Header `X-Astra-Sensor-Token`. Body `IngestBatchRequest`:

```json
{
  "sensorId": "44444444-4444-4444-4444-444444444444",
  "sensorName": "sensor-lab-01",
  "events": [
    {
      "timestamp": "2026-07-09T06:00:00Z",
      "observedTime": "2026-07-09T06:00:00Z",
      "category": "dns",
      "protocol": "udp",
      "applicationProtocol": "dns",
      "sourceIp": "10.30.7.44",
      "destinationIp": "10.30.0.53",
      "sourcePort": 51344,
      "destinationPort": 53,
      "bytesIn": 0, "bytesOut": 74, "packetsIn": 1, "packetsOut": 1,
      "durationMs": null,
      "fields": { "query": "…", "query_type": "TXT", "rcode": "NOERROR" }
    }
  ]
}
```

Response `IngestBatchResponse`: `{ "accepted": N, "rejected": M, "errors": [...] }`.

### `POST /api/ingest/heartbeat`
Header `X-Astra-Sensor-Token`. Body `HeartbeatRequest` (sensor id/name/version + health
sample). Records health and **auto-registers** the sensor on first contact. Response
`{ "acknowledged": true, "configVersion": 1 }`.

## Detection engineering & triage (Phase 3)

### `GET /api/rules`
Returns `DetectionRuleDto[]` — each rule's metadata, `enabled`, thresholds, version, and
live open-detection count.

### `POST /api/rules/{ruleId}`
Body `RuleUpdateRequest` `{ enabled?: bool, thresholds: [{key,value}] }`. Enables/disables
and/or tunes thresholds; bumps the version and writes an audit entry. Takes effect on the
next analysis cycle.

### `POST /api/detections/{id}/triage`
Body `TriageRequest` `{ action, owner?, note?, actor }` where `action` ∈
`close_benign | close_remediated | expected | escalate | in_progress | reopen`. Updates
the detection, rescoring the affected entity, and audits the action. Suppressed
detections stop contributing to score and are not re-raised.

### `GET/POST /api/triage-filters`
List or create `TriageFilter`s (match a detection's tuning fields → suppress scoring /
hide / tag). New detections matching an enabled filter are auto-suppressed.

### `GET/POST /api/allowlists`
List or create `AllowlistEntry`s (ip/cidr/domain/account/port/protocol/sensor).

### `GET /api/audit`
Returns the most recent `AuditEntryDto[]` — actor, action, subject — for every triage,
tuning, and governance operation.

### `GET /api/assistant/entity/{id}`
Read-only, evidence-bound AI investigation summary (fact / inference / recommendation with
citations). See `ai-assistant-security.md`.

## Investigation graph & threat hunting (Phase 4)

### `GET /api/graph/entity/{id}` · `GET /api/graph/incident/{id}`
Return an `InvestigationGraphDto` (`nodes` + `edges`) built from the recent event window:
host↔peer communication, DNS queries, triggered detections, and — for incidents —
shared external infrastructure edges that reveal blast radius across hosts.

### `POST /api/hunt/search`
Body `HuntQueryDto` `{ predicates: [{field, op, value}], windowMinutes, limit }` where `op`
∈ `eq | contains | gt | lt`. Returns `HuntResultDto` — matching rows plus top-destination
and top-source aggregations. Fields include src_ip, dst_ip, domain, sni, user_agent,
account, port, protocol, app, category, direction.

### `GET /api/hunt/templates`
Returns canned `HuntTemplateDto[]` (top external destinations, DNS activity, SMB writes,
remote access, IDS alerts).

## Threat intelligence & response (Phase 5)

### `GET /api/threat-intel/indicators`
Returns `ThreatIndicatorDto[]` — IP/domain/URL/hash IOCs with feed, confidence, and
actor/tool/campaign attribution.

### `POST /api/threat-intel/indicators`
Body `CreateIndicatorRequest` `{ indicator, indicatorType, feedName, confidence, actor?,
createdBy }`. Upserts a single indicator (keyed on `type:value`) and returns the full
indicator list.

### `POST /api/threat-intel/import`
Body `ImportIndicatorsRequest` `{ feedName, csv }`. Parses CSV
`indicator,type,feed,confidence[,actor][,tool][,campaign]` (header/`#` lines skipped) and
returns `ImportResultDto` `{ imported }`.

### `GET /api/threat-intel/feeds`
Returns `ThreatFeedDto[]` — indicators grouped by feed with per-feed counts and last-update.

### `GET /api/threat-intel/matches`
Returns `ThreatMatchDto[]` — recorded matches of an indicator against observed telemetry
(newest first), each linked to the detection it raised.

The matching engine runs every analysis cycle: outbound destinations, DNS queries, TLS SNI,
HTTP host, and file hashes are checked against enabled indicators, raising an evidence-bound
`intel.indicator_match` detection (deduped per rule + entity, MITRE **T1071**).

### `GET /api/response/actions`
Returns `ResponseActionDto[]` (newest first) — kind, target, status, simulation flag,
requester/approver, result.

### `POST /api/response/actions`
Body `RequestResponseActionRequest` `{ kind, target, reason, evidence, actor }`. Creates a
**pending** action. Destructive kinds (`block_ip | block_domain | block_host |
isolate_host_sim | disable_account_sim | add_blocklist_feed`) are forced into simulation
until a real connector is enabled.

### `POST /api/response/actions/{id}/approve` · `POST /api/response/actions/{id}/reject`
Body `ApproveActionRequest` `{ actor }`. Approving a simulated action records the intended
side effect (`SIMULATED: would …`) without touching the network; `add_threat_indicator` has
a real, safe effect. Both write an audit entry. `400` if the action is not pending.

### `GET /api/response/connectors`
Returns `ResponseConnectorDto[]` — SIEM/SOAR/EDR/firewall/webhook connectors with their
`simulationMode` flag and status. Config references env keys only, never secrets.

### `GET /api/incidents/{id}/report`
Returns a plaintext incident report (`text/plain`): summary, kill-chain timeline, related
detections, and recommended containment/investigation. `404` if unknown.

## Roadmap endpoints

The following API groups are defined in the product architecture and delivered in later
phases: saved searches, custom detections, notifications, RBAC/session auth, admin
settings, and live (non-simulated) connector delivery.
