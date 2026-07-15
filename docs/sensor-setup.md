# Astra NDR — Sensor Setup

A sensor is any collector that authenticates with the sensor token and posts normalized
events + heartbeats to the central brain.

## Contract (available now)

- **Heartbeat:** `POST /api/ingest/heartbeat` with `X-Astra-Sensor-Token`. First
  heartbeat auto-registers the sensor (name, version, capabilities from the payload).
- **Events:** `POST /api/ingest/events` with the same header, batching
  `IngestEventDto` records (see [`api-reference.md`](api-reference.md)).
- **Identity:** a stable `sensorId` GUID + `sensorName`. Tag zone/group/location in
  event `fields` (`zone`) and in the profile.
- **Local buffering:** hold events while the brain is unreachable and flush on
  reconnect (`bufferedEvents` reported in health).

The reference implementation is [`lab/demo_sensor.py`](../lab/demo_sensor.py).

## A real field sensor (Phase 2)

Target layout for an Ubuntu sensor:

1. Capture from SPAN/TAP/mirror on a dedicated interface (e.g. `eth1`).
2. Run **Zeek** for protocol metadata and **Suricata** for signatures (EVE JSON).
3. An Astra sensor agent tails Zeek logs + Suricata EVE, normalizes to `IngestEventDto`,
   batches, and posts to the brain; it also emits heartbeats with CPU/RAM/disk/interface,
   packet drop, EPS, and Zeek/Suricata process state.
4. Config sync pulls ruleset assignments and coverage from the brain.

## Health fields

`cpuPercent`, `memoryPercent`, `diskPercent`, `interfaceUp`, `packetDropPercent`,
`eventsPerSecond`, `bufferedEvents`, `zeekRunning`, `suricataRunning`, `errors[]` — all
surfaced on the **Sensor Health** page with per-resource bars and status badges.

## Enrollment security

Phase 1 uses a shared token and auto-registration for streamlined labs. Phase 2 adds a
secure enrollment handshake, per-sensor tokens (stored hashed in `sensors.api_token_hash`),
and revocation.
