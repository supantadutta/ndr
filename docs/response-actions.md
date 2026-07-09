# Astra NDR — Response Actions

Response is **analyst-approved, auditable, and simulation-first**. Schema is present now
(`response_actions`, `response_connectors`); the Response Center + connectors ship in
Phase 5.

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
