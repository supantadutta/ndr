module Astra.Tests.ScoringTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Server.DetectionEngine
open Astra.Tests.Fixtures

/// Build a store with one entity that has real detections, by running the
/// engine over a scan window, then exercise the scoring engine.
let private storeWithDetections () =
    let store = AstraStore()
    let engine = DetectionEngine(store)
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    engine.Run(events, now) |> ignore
    store, now

[<Fact>]
let ``scoring produces positive risk with explanatory factors`` () =
    let store, now = storeWithDetections ()
    Astra.Server.ScoringEngine.recomputeAll store now
    let entity = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    Assert.True(entity.Scores.Risk > 0, "risk should be positive")
    let breakdown = (store.TryGetScoreBreakdown entity.EntityId).Value
    Assert.NotEmpty(breakdown.Factors)
    Assert.Contains(breakdown.Factors, fun f -> f.Kind = ScoreFactorKind.DetectionSeverity)

[<Fact>]
let ``benign triage suppresses the score`` () =
    let store, now = storeWithDetections ()
    Astra.Server.ScoringEngine.recomputeAll store now
    let entity = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    let baseline = entity.Scores.Risk
    // analyst marks benign
    store.UpsertEntity { entity with TriageState = TriageState.ClosedBenign }
    Astra.Server.ScoringEngine.recomputeAll store now
    let after = (store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")).Scores.Risk
    Assert.True(after < baseline, sprintf "benign triage should lower risk (%d -> %d)" baseline after)

[<Fact>]
let ``criticality raises urgency above risk`` () =
    let store, now = storeWithDetections ()
    let entity = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    store.UpsertEntity { entity with Criticality = Criticality.Critical }
    Astra.Server.ScoringEngine.recomputeAll store now
    let e = store.Entities |> List.find (fun e -> e.CanonicalName = "10.0.0.5")
    Assert.True(e.Scores.Urgency >= e.Scores.Risk, "critical asset urgency should be >= risk")
