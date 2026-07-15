# Astra NDR — Response Actions

Response is **analyst-approved, auditable, and simulation-first**. The Response Center,
connector registry, and SIEM/JSON exports are **implemented** ([`Response.fs`](../src/Astra.Server/Response.fs),
[`Operations.fs`](../src/Astra.Shared/Operations.fs)) and surfaced in the **Response Center**
UI page. Schema is present in `response_actions` / `response_connectors`. Live (non-simulated)
connector delivery is enabled per connector out of simulation mode — the engine never performs
a real block/isolate on its own.

## Actions

Add host/domain/IP to blocklist · isolate host (simulation) · disable account
(simulation) · create firewall block feed · create ticket · email/webhook/Slack-Teams
alert · export to SIEM/SOAR/EDR/firewall abstraction · add threat-intel indicator · add
triage filter · add allowlist.

## Non-negotiable guarantees

Every response action **requires analyst approval**, is **auditable**, carries a
**status**, includes **evidence + reason + affected entities**, supports **rollback where
possible**, and runs in **simulation mode** before any real connector is enabled. The AI
assistant may recommend an action but can **never** execute one.

## Action lifecycle

```
pending_approval → approved → executing → completed
                                        ↘ failed
completed → rolled_back    (when rollback is supported)
```

Each transition is written to `audit_logs` with actor, subject, and details.

## Integration targets

Syslog TCP/TLS · raw JSON over TCP · Kafka · Elastic/OpenSearch · Splunk-HEC-style ·
Microsoft-Sentinel-style · Google-SecOps-style · generic webhook · generic REST · generic
SIEM/SOAR exporter · generic EDR connector · generic firewall blocklist feed.

Connectors are modeled behind a provider interface so a real integration slots in without
touching detection/scoring/correlation logic. Connector configs reference environment
keys — **no secrets are stored in the database**.

## API

| Method & path | Purpose |
|---|---|
| `GET /api/response/actions` | List actions (newest first). |
| `POST /api/response/actions` | Request an action `{ kind, target, reason, evidence, actor }`. Destructive kinds are forced into simulation. |
| `POST /api/response/actions/{id}/approve` | Approve + "execute" (simulated side effect recorded, not performed). |
| `POST /api/response/actions/{id}/reject` | Reject a pending action. |
| `GET /api/response/connectors` | List connectors + their `simulationMode` flag. |
| `GET /api/incidents/{id}/report` | Plaintext incident report (summary, kill-chain timeline, related detections, containment). |

Approving a simulated action records `SIMULATED: would <kind> '<target>'` as its result.
`add_threat_indicator` is non-destructive and takes real effect on approval (the target is
added to the analyst feed).

## SIEM / SOAR exports

`Response.toCef` renders an ArcSight-style CEF line
(`CEF:0|AstraNDR|Astra|1.0|<rule>|<title>|<sev>|…`) and `Response.toExportMap` a compact
JSON-ready projection for webhook/SIEM delivery.

## Threat-intel matching

The threat-intel engine ([`ThreatIntel.fs`](../src/Astra.Server/ThreatIntel.fs)) runs every
analysis cycle: outbound destination IPs, DNS queries, TLS SNI, HTTP host, and file hashes are
matched against enabled indicators, raising an evidence-bound `intel.indicator_match` detection
(MITRE **T1071**, deduped per rule + entity) with actor/campaign attribution. IOCs are managed
in the **Threat Intelligence** UI page or imported via
`POST /api/threat-intel/import` (CSV `indicator,type,feed,confidence[,actor][,tool][,campaign]`).
