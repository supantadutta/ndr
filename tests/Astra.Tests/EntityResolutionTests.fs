module Astra.Tests.EntityResolutionTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store

[<Fact>]
let ``resolving the same IP twice returns the same entity`` () =
    let store = AstraStore()
    let now = DateTimeOffset.UtcNow
    let a = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now)
    let b = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now.AddMinutes 5.0)
    Assert.Equal(a.EntityId, b.EntityId)

[<Fact>]
let ``resolution is case-insensitive on canonical name`` () =
    let store = AstraStore()
    let now = DateTimeOffset.UtcNow
    let a = store.ResolveEntity(EntityType.Domain, "Evil.Example.NET", "Evil.Example.NET", now)
    let b = store.ResolveEntity(EntityType.Domain, "evil.example.net", "evil.example.net", now)
    Assert.Equal(a.EntityId, b.EntityId)

[<Fact>]
let ``different entity types with same name are distinct`` () =
    let store = AstraStore()
    let now = DateTimeOffset.UtcNow
    let host = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now)
    let ip = store.ResolveEntity(EntityType.IpAddress, "10.0.0.5", "10.0.0.5", now)
    Assert.NotEqual(host.EntityId, ip.EntityId)

[<Fact>]
let ``resolving updates last seen forward only`` () =
    let store = AstraStore()
    let t0 = DateTimeOffset.UtcNow
    store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", t0) |> ignore
    let later = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", t0.AddHours 1.0)
    Assert.True(later.LastSeen >= t0.AddHours 1.0)
    // an earlier observation must not roll LastSeen backwards
    let earlier = store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", t0.AddMinutes -30.0)
    Assert.True(earlier.LastSeen >= t0.AddHours 1.0)

[<Fact>]
let ``classifier assigns traffic direction from CIDR coverage`` () =
    let classifier = Astra.Server.Classification.Classifier(CoverageConfig.empty)
    Assert.Equal(TrafficDirection.InternalToInternal, classifier.Direction("10.0.0.5", "10.0.0.9"))
    Assert.Equal(TrafficDirection.InternalToExternal, classifier.Direction("10.0.0.5", "203.0.113.9"))
    Assert.Equal(TrafficDirection.ExternalToInternal, classifier.Direction("203.0.113.9", "10.0.0.5"))
    Assert.Equal(TrafficDirection.ExternalToExternal, classifier.Direction("8.8.8.8", "203.0.113.9"))
