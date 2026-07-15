module Astra.Tests.OperationsTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Tests.Fixtures

/// Phase 5: threat-intel matching, approval-gated response, and SIEM export.

let private badIp = "203.0.113.66"

let private storeWithIndicator () =
    let store = AstraStore()
    let now = DateTimeOffset.UtcNow
    store.UpsertIndicator
        { IndicatorId = Guid.NewGuid(); Indicator = badIp; IndicatorType = IndicatorType.Ip
          FeedName = "unit-feed"; ActorLabel = Some "TEST-ACTOR"; ToolLabel = None; CampaignLabel = None
          Confidence = 90; FirstSeen = now; LastSeen = now; ExpiresAt = None; Enabled = true }
    store

[<Fact>]
let ``threat intel raises a detection for a matching outbound destination`` () =
    let store = storeWithIndicator ()
    let now = DateTimeOffset.UtcNow
    let e =
        mkEvent EventCategory.NetworkConnection AppProtocol.Tls "10.0.0.5" badIp now
        |> withDirection TrafficDirection.InternalToExternal
    store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now) |> ignore
    store.AddEvent e
    let window = store.RecentEvents(TimeSpan.FromHours 1.0)
    let detections = Astra.Server.ThreatIntel.scan store window now
    Assert.Single(detections) |> ignore
    let d = List.head detections
    Assert.Equal(DetectionEngineKind.ThreatIntel, d.EngineKind)
    Assert.Equal(Severity.Critical, d.Severity)   // confidence 90 => critical
    Assert.Contains("TEST-ACTOR", d.Summary)
    // one match recorded
    Assert.Single(store.IntelMatches) |> ignore

[<Fact>]
let ``threat intel dedupes a repeated match per rule and entity`` () =
    let store = storeWithIndicator ()
    let now = DateTimeOffset.UtcNow
    store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now) |> ignore
    for _ in 1 .. 2 do
        store.AddEvent (mkEvent EventCategory.NetworkConnection AppProtocol.Tls "10.0.0.5" badIp now |> withDirection TrafficDirection.InternalToExternal)
    let window = store.RecentEvents(TimeSpan.FromHours 1.0)
    let first = Astra.Server.ThreatIntel.scan store window now
    Assert.Single(first) |> ignore
    // a second scan must not re-fire while the detection is open
    let second = Astra.Server.ThreatIntel.scan store window now
    Assert.Empty(second)

[<Fact>]
let ``non-matching destination produces no intel detection`` () =
    let store = storeWithIndicator ()
    let now = DateTimeOffset.UtcNow
    store.AddEvent (mkEvent EventCategory.NetworkConnection AppProtocol.Tls "10.0.0.5" "198.51.100.200" now |> withDirection TrafficDirection.InternalToExternal)
    let window = store.RecentEvents(TimeSpan.FromHours 1.0)
    Assert.Empty(Astra.Server.ThreatIntel.scan store window now)

[<Fact>]
let ``destructive response action is forced into simulation and awaits approval`` () =
    let store = AstraStore()
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp badIp "malicious C2" [] [] "analyst"
    Assert.True(action.Simulation)
    Assert.Equal(ResponseStatus.PendingApproval, action.Status)

[<Fact>]
let ``approving a simulated action completes it without a real side effect`` () =
    let store = AstraStore()
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp badIp "malicious C2" [] [] "analyst"
    match Astra.Server.Response.approve store action.ActionId "lead" with
    | Error e -> failwithf "expected approval to succeed: %s" e
    | Ok updated ->
        Assert.Equal(ResponseStatus.Completed, updated.Status)
        Assert.Equal(Some "lead", updated.ApprovedBy)
        Assert.StartsWith("SIMULATED:", defaultArg updated.Result "")

[<Fact>]
let ``approving twice is rejected because the action is no longer pending`` () =
    let store = AstraStore()
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp badIp "malicious C2" [] [] "analyst"
    Astra.Server.Response.approve store action.ActionId "lead" |> ignore
    match Astra.Server.Response.approve store action.ActionId "lead" with
    | Error _ -> ()
    | Ok _ -> failwith "second approval should have been rejected"

[<Fact>]
let ``add threat indicator action has a real effect on approval`` () =
    let store = AstraStore()
    let action = Astra.Server.Response.request store ResponseActionKind.AddThreatIndicator badIp "seen in incident" [] [] "analyst"
    Assert.False(action.Simulation)  // not destructive
    Astra.Server.Response.approve store action.ActionId "lead" |> ignore
    Assert.True((store.TryMatchIndicator(IndicatorType.Ip, badIp)).IsSome)

[<Fact>]
let ``CEF export renders a well-formed line`` () =
    let store = storeWithIndicator ()
    let now = DateTimeOffset.UtcNow
    let e = mkEvent EventCategory.NetworkConnection AppProtocol.Tls "10.0.0.5" badIp now |> withDirection TrafficDirection.InternalToExternal
    store.ResolveEntity(EntityType.Host, "10.0.0.5", "10.0.0.5", now) |> ignore
    store.AddEvent e
    let d = Astra.Server.ThreatIntel.scan store (store.RecentEvents(TimeSpan.FromHours 1.0)) now |> List.head
    let cef = Astra.Server.Response.toCef store d
    Assert.StartsWith("CEF:0|AstraNDR|Astra|1.0|", cef)
    Assert.Contains("dhost=", cef)
    Assert.Contains("AstraTactic=", cef)

[<Fact>]
let ``CSV import parses indicators with attribution`` () =
    let store = AstraStore()
    let csv = "indicator,type,feed,confidence,actor\n" +
              "evil.example.net,domain,imported,85,IMPORT-ACTOR\n" +
              "# comment line\n" +
              "203.0.113.99,ip,imported,70\n"
    let count = Astra.Server.ThreatIntel.importCsv store "imported" csv
    Assert.Equal(2, count)
    match store.TryMatchIndicator(IndicatorType.Domain, "evil.example.net") with
    | Some i -> Assert.Equal(Some "IMPORT-ACTOR", i.ActorLabel)
    | None -> failwith "expected imported domain indicator"
