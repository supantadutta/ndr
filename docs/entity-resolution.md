# Astra NDR — Entity Resolution

Source: `AstraStore.ResolveEntity` in
[`src/Astra.Server/Store.fs`](../src/Astra.Server/Store.fs); types in
[`src/Astra.Shared/Entities.fs`](../src/Astra.Shared/Entities.fs).

Astra reasons about **entities** (hosts, accounts, domains, external destinations, …),
not raw IPs. Resolution maps observations to a stable canonical entity.

## Find-or-create

`ResolveEntity(entityType, canonicalName, displayName, now)`:
- Looks up `(entityType, lower(canonicalName))` in an index.
- Returns the existing profile (bumping `LastSeen`) or creates a new one with a fresh
  `EntityId`, default criticality/behavior/scores, and `IdentitySources = ["network_observation"]`.

During ingestion the source host is resolved eagerly, so entities appear in the queue as
soon as telemetry arrives. Detection rules resolve source/target/domain entities as they
build drafts, which also links related entities for the attack graph.

## Entity profile

`EntityProfile` (see the spec's field list) includes identity (id/type/display/canonical
/aliases), lifecycle (first/last seen, last sensor), confidence & criticality, business
context (unit/owner/location/tags/groups), **behavior baseline** (`BehaviorProfile`:
normal protocols/ports/peers/login sources/hours/external destinations/DNS rate/byte
volume), the four scores, related detection/incident counts, analyst notes, and triage
state.

## Groups & importance

`EntityGroup` supports static members, hostname/account **regex**, IP **CIDR**, and
**AD-imported** membership rules, each with an `ImportanceWeight` and a
critical-asset flag. Group importance and asset criticality feed the scoring engine's
urgency calculation, floating high-value assets to the top of the queue.

## Correlation the resolver enables

Because observations collapse onto canonical entities, Astra can express: IP↔host,
hostname↔asset, MAC↔asset, DHCP lease↔asset, DNS name↔asset, user↔host, account↔auth
behavior, cloud identity↔activity, and public IP/domain↔external entity — and build a
per-entity timeline across sensors.

## Roadmap

Phase 3 adds DHCP/DNS/AD-driven alias enrichment, identity confidence scoring, and
persistence of `entity_aliases` / `entity_observations` (schema already present in
migration 0001).
