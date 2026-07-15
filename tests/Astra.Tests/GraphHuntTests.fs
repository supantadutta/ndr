module Astra.Tests.GraphHuntTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Server.Hunt
open Astra.Tests.Fixtures

/// Populate a store with a small window of events (some via entity resolution).
let private storeWithEvents () =
    let store = AstraStore()
    let now = DateTimeOffset.UtcNow
    // internal->external TLS to a shared destination from two hosts
    for host in [ "10.0.0.5"; "10.0.0.6" ] do
        let e =
            mkEvent EventCategory.Tls AppProtocol.Tls host "203.0.113.9" now
            |> withDirection TrafficDirection.InternalToExternal
        store.ResolveEntity(EntityType.Host, host, host, now) |> ignore
        store.AddEvent e
    // a DNS query
    let dns =
        let e = mkEvent EventCategory.Dns AppProtocol.Dns "10.0.0.5" "10.0.0.53" now
        { e with Payload = EventPayload.Dns { Query = "evil.example.net"; QueryType = "A"; ResponseCode = "NOERROR"; Answers = []; QueryLength = 16; IsNxDomain = false; IsTxtQuery = false } }
    store.AddEvent dns
    store

[<Fact>]
let ``hunt filters by category`` () =
    let store = storeWithEvents ()
    let result = run store { Predicates = [ { Field = "category"; Op = "eq"; Value = "dns" } ]; WindowMinutes = 60; Limit = 100 }
    Assert.Equal(1, result.Total)

[<Fact>]
let ``hunt filters by direction and aggregates top destinations`` () =
    let store = storeWithEvents ()
    let result = run store { Predicates = [ { Field = "direction"; Op = "eq"; Value = "internal_to_external" } ]; WindowMinutes = 60; Limit = 100 }
    Assert.Equal(2, result.Total)
    let top = List.head result.TopDestinations
    Assert.Equal("203.0.113.9", top.Key)
    Assert.Equal(2, top.Count)

[<Fact>]
let ``hunt contains operator matches domain substring`` () =
    let store = storeWithEvents ()
    let result = run store { Predicates = [ { Field = "domain"; Op = "contains"; Value = "evil" } ]; WindowMinutes = 60; Limit = 100 }
    Assert.Equal(1, result.Total)

[<Fact>]
let ``entity graph centres on the host and includes peers`` () =
    let store = storeWithEvents ()
    let host = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", DateTimeOffset.UtcNow)
    let window = store.RecentEvents(TimeSpan.FromHours 1.0)
    let graph = Astra.Server.Graph.entityGraph store window host.EntityId
    Assert.NotEmpty(graph.Nodes)
    // the centre host node must be present
    Assert.Contains(graph.Nodes, fun n -> n.Kind = GraphNodeKind.Host && n.Label = "10.0.0.5")
    // it communicated with the external destination and queried a domain
    Assert.Contains(graph.Edges, fun e -> e.Kind = GraphEdgeKind.CommunicatedWith)
    Assert.Contains(graph.Nodes, fun n -> n.Kind = GraphNodeKind.Domain)

[<Fact>]
let ``hunt templates are well-formed`` () =
    Assert.NotEmpty(templates)
    Assert.All(templates, fun t -> Assert.False(String.IsNullOrWhiteSpace t.Id))
