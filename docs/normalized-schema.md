# Astra NDR — Normalized Event Schema

Every telemetry source is normalized into a single common envelope plus a typed
protocol payload. The authoritative definition lives in
[`src/Astra.Shared/Events.fs`](../src/Astra.Shared/Events.fs).

## The common envelope: `NormalizedEvent`

| Field | Type | Notes |
|-------|------|-------|
| `EventId` | `EventId` (GUID) | unique per event |
| `Timestamp` | `DateTimeOffset` | when it happened on the wire |
| `ObservedTime` | `DateTimeOffset` | when the sensor observed/emitted it |
| `IngestTime` | `DateTimeOffset` | when the brain accepted it |
| `SourceSensorId` / `SourceSensorName` / `SourceZone` | | provenance |
| `CollectorType` | DU | network / cloud / identity / saas / lab / internal |
| `Category` | `EventCategory` | see list below |
| `Protocol` / `ApplicationProtocol` | DU | tcp/udp/icmp/sctp · dns/http/tls/smb/… |
| `SourceIp` / `DestinationIp` / `SourcePort` / `DestinationPort` | | 5-tuple |
| `SourceMac` / `DestinationMac` | | link layer |
| `Hostname` / `SourceHostname` / `DestinationHostname` | | resolved names |
| `Username` / `AccountName` / `DomainName` | | identity |
| `DeviceId` / `AssetId` / `UserId` / `SessionId` / `ConnectionId` | | correlation keys |
| `Direction` | `TrafficDirection` | internal↔external classification |
| `Lane` | `TrafficLane` | north-south / east-west / DC / campus / … |
| `BytesIn` / `BytesOut` / `PacketsIn` / `PacketsOut` / `DurationMs` | | volume |
| `Country` / `Asn` | | geo/ASN enrichment |
| `Payload` | `EventPayload` (DU) | typed protocol detail |
| `RiskHint` / `SeverityHint` / `ConfidenceHint` | | producer hints |
| `RawEventReference` | | pointer into raw telemetry store |
| `Enrichment` | `Map<string,string>` | extensible enrichment |
| `Tags` | `string list` | free-form tags |

## Event categories (`EventCategory`)

`network_connection`, `dns`, `http`, `tls`, `x509_certificate`, `smb_session`,
`smb_file`, `smb_named_pipe`, `dcerpc`, `rdp`, `ssh`, `ldap`, `kerberos`, `ntlm`,
`dhcp`, `smtp`, `ftp`, `ntp`, `icmp`, `vpn_remote_user`, `proxy`,
`ids_signature_alert`, `ids_protocol_alert`, `ids_decoder_event`, `file_metadata`,
`threat_intel_match`, `cloud_audit`, `saas_audit`, `identity_authentication`,
`sensor_health`, `system_audit`, `detection`, `incident`, `response_action`.

## Typed payloads (`EventPayload`)

The payload is a discriminated union so each protocol carries exactly the fields that
make sense for it — no sparse mega-row:

- `Dns` — query, type, rcode, answers, length, NXDOMAIN flag, TXT flag
- `Http` — method, host, uri, status, user-agent, body lengths, content-type
- `Tls` — SNI, version, cipher, cert subject/issuer/validity, JA3/JA4-style fingerprints
- `Smb` — share, file path, named pipe, operation, admin-share flag
- `Dcerpc` — interface UUID, opnum, operation name, endpoint
- `Auth` — protocol, target service, result, failure reason, privileged flag, logon type
- `Dhcp`, `IdsAlert`, `FileMetadata`, `CloudAudit`, `SaasAudit`, `ThreatIntelMatch`
- `Connection` — flow record with no extra payload
- `Generic of Map<string,string>` — escape hatch for sources not yet typed

## Wire format (ingestion)

Sensors send `IngestEventDto` (see [`Api.fs`](../src/Astra.Shared/Api.fs)): a flat
record with a `Fields: Map<string,string>` bag for protocol-specific values. The server
(`Ingestion.Mapping`) lifts those fields into the correct typed payload during
normalization. This keeps the sensor-side contract simple and forward-compatible while
the server owns the typed model.

Dates travel as ISO-8601 strings and enums as canonical string labels, so
System.Text.Json (server) and Thoth.Json (client) interoperate with no custom
converters.
