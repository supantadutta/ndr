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

## Roadmap endpoints

The following API groups are defined in the product architecture and delivered in later
phases: metadata search & threat hunting, saved searches, custom detections, detection
engineering/tuning, triage filters, allowlists, threat intel, response actions,
notifications, audit logs, admin settings, and the read-only AI assistant.
