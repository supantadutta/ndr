# Astra NDR — Attack Graph & Investigation

> **Status: implemented (Phase 4).** The graph engine (`src/Astra.Server/Graph.fs`) builds
> an `InvestigationGraph` around an entity or incident and is served at
> `GET /api/graph/entity/{id}` and `GET /api/graph/incident/{id}`; the console renders it as
> a radial SVG graph on the **Attack Graph** page. Incident graphs add shared-infrastructure
> edges (external destinations contacted by ≥2 involved hosts) for blast-radius analysis.

Types are defined in [`src/Astra.Shared/Incidents.fs`](../src/Astra.Shared/Incidents.fs)
(`InvestigationGraph`, `GraphNode`, `GraphEdge`); the graph engine + UI land in Phase 4.

## Node & edge model

**Nodes** (`GraphNodeKind`): host, account, domain, ip, sensor, detection, incident,
service, cloud resource, SaaS object, threat indicator — each with a risk score and
optional linked `EntityId`.

**Edges** (`GraphEdgeKind`): communicated-with, authenticated-to, queried-DNS,
connected-to, used-protocol, triggered-detection, targeted-entity, shared-C2-
infrastructure, same-account-used-on-host, same-domain-contacted, same-threat-indicator,
same-incident-membership — each with first/last seen and a weight.

## Views (Phase 4)

Radial attack graph · attack-flow tree · attack timeline · entity relationship graph ·
communication graph · blast-radius graph · C2 infrastructure graph · identity-to-host ·
cloud identity-to-resource.

## Interaction

Time / protocol / risk / MITRE-tactic filtering, entity search, expand/collapse neighbors,
focused view to reduce clutter, export graph as JSON, and export an investigation report.

## How Phase 1 feeds it

Detections already record source/target/related entities and shared infrastructure
(e.g. multiple hosts contacting the same external destination in `c2.beaconing` /
`exfil.large_upload_rare_destination`). The correlation engine already computes affected
entities and blast radius per incident — these are exactly the nodes and edges the graph
engine will render.
