# Astra NDR — Zeek & Suricata Ingestion

Astra treats Zeek and Suricata as first-class sensor sources. Phase 1 defines the
normalized target model and the ingest contract; Phase 2 ships the parsers.

## Mapping to the normalized schema

| Source | Astra category | Typed payload |
|--------|----------------|---------------|
| Zeek `conn.log` | `network_connection` | `Connection` (bytes/packets/duration) |
| Zeek `dns.log` | `dns` | `Dns` (query, type, rcode, answers, TXT/NXDOMAIN) |
| Zeek `http.log` | `http` | `Http` (method, host, uri, user-agent, status) |
| Zeek `ssl.log` / `x509.log` | `tls` / `x509_certificate` | `Tls` (SNI, version, cipher, cert, JA3/JA4) |
| Zeek `smb_*.log` | `smb_session`/`smb_file`/`smb_named_pipe` | `Smb` (share, path, pipe, op, admin) |
| Zeek `dce_rpc.log` | `dcerpc` | `Dcerpc` (interface UUID, opnum, endpoint) |
| Zeek `kerberos.log`/`ntlm.log` | `kerberos`/`ntlm` | `Auth` (service, result, privileged) |
| Zeek `dhcp.log` | `dhcp` | `Dhcp` (assigned ip, lease, client) |
| Suricata EVE `alert` | `ids_signature_alert` | `IdsAlert` (sid, rev, category, severity) |
| Suricata EVE `dns`/`http`/`tls`/`flow` | matching category | matching payload |
| Suricata fast.log | `ids_signature_alert` | `IdsAlert` (parsed line) |

## Ingest contract

The sensor agent parses each log line, fills an `IngestEventDto` with the 5-tuple,
volume fields, and protocol-specific values in `fields`, then batches to
`POST /api/ingest/events`. The brain's `Ingestion.Mapping` lifts `fields` into the typed
payload (see [`normalized-schema.md`](normalized-schema.md)).

## Suricata alert formats

Supported/target formats: raw EVE **JSON**, **fast.log**, **CEF**, **syslog**, Kafka
message, and Elastic/OpenSearch document. Signature alerts correlate with behavioral
detections in the engine (Phase 3), and a signature match can be promoted to a custom
detection.

## PCAP replay

For offline analysis and the lab, a sensor in `PcapReplay` mode runs Zeek/Suricata over
a capture file and ingests the resulting logs through the same path — identical
normalization, identical detections.
