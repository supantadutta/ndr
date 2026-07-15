module Astra.Server.Graph

open System
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Investigation graph engine.
///
/// Builds an `InvestigationGraph` (typed nodes + edges) centered on an entity or
/// an incident, from live detections and the recent event window. Communication
/// edges come from observed traffic; detection/incident edges come from the
/// analysis layer; shared-infrastructure edges reveal blast radius across hosts.
/// ============================================================================

let private nodeId (prefix: string) (key: string) = sprintf "%s:%s" prefix key

let private hostNode (store: AstraStore) (ip: string) (now: DateTimeOffset) =
    let e = store.ResolveEntity(EntityType.Host, ip, ip, now)
    { NodeId = nodeId "host" ip
      Kind = GraphNodeKind.Host
      Label = e.DisplayName
      EntityId = Some e.EntityId
      Risk = e.Scores.Risk
      Tags = [ "internal" ] }

let private externalNode (ip: string) =
    { NodeId = nodeId "ext" ip; Kind = GraphNodeKind.Ip; Label = ip; EntityId = None; Risk = 0; Tags = [ "external" ] }

let private domainNode (d: string) =
    { NodeId = nodeId "domain" d; Kind = GraphNodeKind.Domain; Label = d; EntityId = None; Risk = 0; Tags = [] }

let private detectionNode (d: Detection) =
    { NodeId = nodeId "det" (let (DetectionId g) = d.DetectionId in string g)
      Kind = GraphNodeKind.Detection
      Label = d.Title
      EntityId = None
      Risk = d.ThreatScore
      Tags = [ DetectionCategory.label d.Category; Severity.label d.Severity ] }

let private edge fromN toN kind label (first: DateTimeOffset) (last: DateTimeOffset) weight =
    { EdgeId = sprintf "%s->%s:%s" fromN toN label
      FromNode = fromN; ToNode = toN; Kind = kind; Label = label
      FirstSeen = first; LastSeen = last; Weight = weight }

/// Build a focused graph around a single host entity: its peers (internal +
/// external), the domains it queried, and the detections it triggered.
let entityGraph (store: AstraStore) (window: NormalizedEvent list) (entityId: EntityId) : InvestigationGraph =
    match store.TryGetEntity entityId with
    | None -> { Nodes = []; Edges = [] }
    | Some entity ->
        let now = DateTimeOffset.UtcNow
        let ip = entity.CanonicalName
        let center = hostNode store ip now
        let related = window |> List.filter (fun e -> e.SourceIp = ip || e.DestinationIp = ip)

        let nodes = System.Collections.Generic.Dictionary<string, GraphNode>()
        let edges = System.Collections.Generic.Dictionary<string, GraphEdge>()
        nodes.[center.NodeId] <- center
        let addNode (n: GraphNode) = if not (nodes.ContainsKey n.NodeId) then nodes.[n.NodeId] <- n
        let addEdge (e: GraphEdge) =
            match edges.TryGetValue e.EdgeId with
            | true, existing ->
                edges.[e.EdgeId] <- { existing with Weight = existing.Weight + e.Weight; LastSeen = max existing.LastSeen e.LastSeen; FirstSeen = min existing.FirstSeen e.FirstSeen }
            | _ -> edges.[e.EdgeId] <- e

        // communication + protocol + DNS edges
        for ev in related do
            let peerIp = if ev.SourceIp = ip then ev.DestinationIp else ev.SourceIp
            let internalPeer =
                match ev.Direction with
                | TrafficDirection.InternalToInternal -> true
                | _ -> (ev.SourceIp = ip && (ev.Direction = TrafficDirection.InternalToInternal))
            let peerNode = if internalPeer then hostNode store peerIp now else externalNode peerIp
            addNode peerNode
            let label = AppProtocol.label ev.ApplicationProtocol
            addEdge (edge center.NodeId peerNode.NodeId GraphEdgeKind.CommunicatedWith label ev.Timestamp ev.Timestamp 1.0)
            match ev.Payload with
            | EventPayload.Dns d when d.Query <> "" ->
                let dn = domainNode d.Query
                addNode dn
                addEdge (edge center.NodeId dn.NodeId GraphEdgeKind.QueriedDns "dns" ev.Timestamp ev.Timestamp 1.0)
            | _ -> ()

        // detection edges
        for d in store.Detections |> List.filter (fun d -> d.AffectedEntity = entityId && d.Status = "open") do
            let dn = detectionNode d
            addNode dn
            addEdge (edge center.NodeId dn.NodeId GraphEdgeKind.TriggeredDetection (DetectionCategory.label d.Category) d.CreatedAt d.CreatedAt 2.0)

        { Nodes = nodes.Values |> Seq.toList; Edges = edges.Values |> Seq.toList }

/// Build a graph for an incident: primary + affected entities, their detections,
/// and shared external infrastructure that links multiple internal hosts (the
/// blast-radius view).
let incidentGraph (store: AstraStore) (window: NormalizedEvent list) (incidentId: IncidentId) : InvestigationGraph =
    match store.TryGetIncident incidentId with
    | None -> { Nodes = []; Edges = [] }
    | Some inc ->
        let now = DateTimeOffset.UtcNow
        let nodes = System.Collections.Generic.Dictionary<string, GraphNode>()
        let edges = System.Collections.Generic.Dictionary<string, GraphEdge>()
        let addNode (n: GraphNode) = if not (nodes.ContainsKey n.NodeId) then nodes.[n.NodeId] <- n
        let addEdge (e: GraphEdge) = if not (edges.ContainsKey e.EdgeId) then edges.[e.EdgeId] <- e

        // incident node
        let incNode =
            { NodeId = nodeId "inc" (let (IncidentId g) = incidentId in string g)
              Kind = GraphNodeKind.Incident; Label = inc.Title; EntityId = None
              Risk = inc.Urgency; Tags = [ string inc.AttackProfile ] }
        addNode incNode

        // affected entity + detection nodes
        let hostIps =
            inc.AffectedEntities
            |> List.choose (fun eid -> store.TryGetEntity eid)
            |> List.filter (fun e -> e.EntityType = EntityType.Host)
            |> List.map (fun e -> e.CanonicalName)
            |> List.distinct
        for ip in hostIps do
            let hn = hostNode store ip now
            addNode hn
            addEdge (edge incNode.NodeId hn.NodeId GraphEdgeKind.TargetedEntity "affected" inc.CreatedAt inc.UpdatedAt 1.0)

        for did in inc.RelatedDetections do
            match store.TryGetDetection did with
            | Some d ->
                let dn = detectionNode d
                addNode dn
                addEdge (edge incNode.NodeId dn.NodeId GraphEdgeKind.SameIncidentMembership "detection" d.CreatedAt d.CreatedAt 1.0)
                match store.TryGetEntity d.AffectedEntity with
                | Some e when e.EntityType = EntityType.Host ->
                    addEdge (edge (nodeId "host" e.CanonicalName) dn.NodeId GraphEdgeKind.TriggeredDetection (DetectionCategory.label d.Category) d.CreatedAt d.CreatedAt 1.0)
                | _ -> ()
            | None -> ()

        // shared external infrastructure: external dests contacted by >1 involved host
        let hostSet = Set.ofList hostIps
        let externalHits =
            window
            |> List.filter (fun e -> e.Direction = TrafficDirection.InternalToExternal && Set.contains e.SourceIp hostSet)
            |> List.groupBy (fun e -> e.DestinationIp)
            |> List.filter (fun (_, evts) -> (evts |> List.map (fun e -> e.SourceIp) |> List.distinct |> List.length) >= 2)
        for (dstIp, evts) in externalHits do
            let en = externalNode dstIp
            addNode { en with Tags = "shared-infra" :: en.Tags; Risk = 60 }
            for srcIp in evts |> List.map (fun e -> e.SourceIp) |> List.distinct do
                if Set.contains srcIp hostSet then
                    addEdge (edge (nodeId "host" srcIp) en.NodeId GraphEdgeKind.SharedC2Infrastructure "shared external destination"
                                (evts |> List.map (fun e -> e.Timestamp) |> List.min)
                                (evts |> List.map (fun e -> e.Timestamp) |> List.max) 2.0)

        { Nodes = nodes.Values |> Seq.toList; Edges = edges.Values |> Seq.toList }
