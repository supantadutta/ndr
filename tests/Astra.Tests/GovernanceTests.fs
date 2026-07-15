module Astra.Tests.GovernanceTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Server.DetectionEngine
open Astra.Tests.Fixtures

let private authEvent result (src: string) (account: string) at =
    let e = mkEvent EventCategory.Kerberos AppProtocol.Kerberos src "10.0.0.10" at
    { e with
        AccountName = Some account
        Payload = EventPayload.Auth
            { AuthProtocol = "kerberos"; TargetService = Some "cifs/dc"; Result = result
              FailureReason = None; IsPrivileged = false; LogonType = Some "network" } }

[<Fact>]
let ``password spray rule fires on breadth across accounts`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 10 -> authEvent "failure" "10.0.0.99" (sprintf "user%d" i) (now.AddSeconds(float i)) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)
    let detections = engine.Run(events, now)
    Assert.Contains(detections, fun d -> d.RuleId = RuleId "cred.password_spray")

[<Fact>]
let ``internal fan-out rule fires over remote-access ports`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 12 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i + 20)) (now.AddSeconds(float i))
            |> withPorts (Some 40000) (Some 445) ]
    let store = AstraStore()
    let detections = DetectionEngine(store).Run(events, now)
    Assert.Contains(detections, fun d -> d.RuleId = RuleId "lateral.internal_fanout")

[<Fact>]
let ``disabling a rule stops it from firing`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)
    // disable the scan rule via store config
    match store.TryGetRuleConfig(RuleId "recon.internal_port_scan") with
    | Some def -> store.UpsertRuleConfig { def with Enabled = false }
    | None -> ()
    let detections = engine.Run(events, now)
    Assert.DoesNotContain(detections, fun d -> d.RuleId = RuleId "recon.internal_port_scan")

[<Fact>]
let ``lowering a threshold makes a rule fire on smaller input`` () =
    let now = DateTimeOffset.UtcNow
    // only 12 distinct hosts / ports — below the default 50/100
    let events =
        [ for i in 1 .. 12 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" i) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some (1000 + i)) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)
    // default: should not fire
    Assert.DoesNotContain(engine.Run(events, now), fun d -> d.RuleId = RuleId "recon.internal_port_scan")
    // tune down the host threshold, then it should fire
    match store.TryGetRuleConfig(RuleId "recon.internal_port_scan") with
    | Some def -> store.UpsertRuleConfig { def with Thresholds = def.Thresholds |> Map.add "distinct_hosts" 10.0 }
    | None -> ()
    Assert.Contains(engine.Run(events, now), fun d -> d.RuleId = RuleId "recon.internal_port_scan")

[<Fact>]
let ``closing a detection as benign prevents it re-firing on the next cycle`` () =
    // Reproduces the live-worker scenario: after an analyst closes a finding,
    // the next analysis cycle must NOT immediately re-raise it (which would pin
    // the entity's score). Dedup treats dismissed findings as already-handled.
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)

    // cycle 1: rule fires
    let first = engine.Run(events, now)
    let scan = first |> List.find (fun d -> d.RuleId = RuleId "recon.internal_port_scan")

    // analyst closes it as benign
    store.UpdateDetection { scan with Status = "closed"; TriageState = TriageState.ClosedBenign }

    // cycle 2: same evidence — must NOT create a new open scan detection
    let second = engine.Run(events, now.AddSeconds 5.0)
    Assert.DoesNotContain(second, fun d -> d.RuleId = RuleId "recon.internal_port_scan")

    // score reflects the dismissal
    Astra.Server.ScoringEngine.recomputeAll store (now.AddSeconds 5.0)
    let entity = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    Assert.Equal(0, entity.Scores.Risk)

[<Fact>]
let ``a matching triage filter suppresses a detection's scoring`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)
    // create a filter matching the scan rule's tuning fields
    store.UpsertTriageFilter
        { FilterId = Guid.NewGuid(); Name = "known scanner"; Description = ""
          Conditions = [ "source_ip", "10.0.0.5"; "detection_type", "recon.internal_port_scan" ]
          Action = TriageAction.SuppressScoring; CreatedBy = "test"
          CreatedAt = now; Enabled = true }
    let detections = engine.Run(events, now)
    let scan = detections |> List.find (fun d -> d.RuleId = RuleId "recon.internal_port_scan")
    Assert.Equal(TriageState.ExpectedBehavior, scan.TriageState)
    // scoring should exclude the suppressed detection
    Astra.Server.ScoringEngine.recomputeAll store now
    let entity = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    Assert.Equal(0, entity.Scores.Risk)
