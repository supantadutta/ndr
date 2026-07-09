# Astra NDR — Threat Hunting

Historical metadata search and hunting land in Phase 4, over the normalized-event store
(`normalized_events` in Postgres for the working window; ClickHouse for volume). Schema
support (`saved_searches`, `custom_models`) is present in migration 0001.

## Search dimensions

Source/destination IP, hostname, account, domain, DNS query, URL, user-agent, TLS SNI,
TLS fingerprint, certificate subject/issuer, SMB share/path, RPC UUID/operation, Kerberos
service, protocol, port, sensor, zone, direction, MITRE technique, detection id, incident
id, threat-intel indicator, time range, risk-score threshold.

## Features

Query builder · saved searches · scheduled searches · **convert a saved search into a
custom detection** · result visualization · host/account/domain/external-destination
investigations · full timeline around a detection · metadata pivots · dashboards and
reports from a query.

## Hunt templates

Top external destinations by connection count · DNS tunneling indicators · long DNS
queries with TXT records · high-NXDOMAIN sources · lateral RDP sessions · SMB fanout ·
new external destinations · rare SNI · direct-IP HTTPS · suspicious remote execution ·
large upload to rare destination · first-seen domain contacted by many hosts · same C2
destination across multiple entities.

## Relationship to detections

Several starter detections are effectively saved hunts promoted to always-on rules
(beaconing, DNS tunnel, rare-destination exfil). The Phase-4 "convert query to detection"
flow formalizes that path: hunt → validate → promote to an `IDetectionRule`-backed custom
detection.
