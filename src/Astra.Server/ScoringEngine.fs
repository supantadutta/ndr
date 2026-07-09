module Astra.Server.ScoringEngine

open System
open Astra.Shared
open Astra.Server.Store

/// Explainable entity scoring. Every score is the clamped sum of named,
/// signed factors so the UI can show exactly why an entity ranks where it does.

let private clamp v = max 0 (min 100 (int (Math.Round(v: float))))

/// Recompute an entity's scores from its open detections + context.
let computeBreakdown (store: AstraStore) (now: DateTimeOffset) (entity: EntityProfile) : ScoreBreakdown =
    let detections =
        store.Detections
        |> List.filter (fun d -> d.AffectedEntity = entity.EntityId && d.Status = "open")

    let mutable factors : ScoreFactor list = []
    let add kind label contribution explanation related =
        factors <- { Kind = kind; Label = label; Contribution = contribution
                     Explanation = explanation; RelatedDetections = related } :: factors

    // --- base threat from strongest detections (severity + confidence) ---
    let severityScore =
        detections
        |> List.sumBy (fun d ->
            let s = float (Severity.toInt d.Severity)
            let c = float d.Confidence / 100.0
            // diminishing returns: each additional detection contributes less
            s * c * 0.4)
    if severityScore > 0.0 then
        add ScoreFactorKind.DetectionSeverity "Detection severity & confidence" severityScore
            (sprintf "%d open detection(s), weighted by severity and confidence" detections.Length)
            (detections |> List.map (fun d -> d.DetectionId))

    // --- category breadth: multiple attack categories => coordinated activity ---
    let categories = detections |> List.map (fun d -> d.Category) |> List.distinct
    if categories.Length >= 2 then
        let contrib = float categories.Length * 6.0
        add ScoreFactorKind.CategoryBreadth "Attack category breadth" contrib
            (sprintf "activity spans %d distinct attack categories" categories.Length) []

    // --- kill-chain progression: later stages weigh more ---
    match detections with
    | [] -> ()
    | _ ->
        let maxStage = detections |> List.map (fun d -> KillChainStage.ordinal d.KillChainStage) |> List.max
        if maxStage >= 4 then
            let contrib = float maxStage * 3.0
            add ScoreFactorKind.KillChainProgression "Kill-chain progression" contrib
                (sprintf "reached kill-chain stage ordinal %d (installation or later)" maxStage) []

    // --- velocity: many detections in a short span ---
    match detections with
    | first :: _ ->
        let span = (now - (detections |> List.map (fun d -> d.CreatedAt) |> List.min)).TotalMinutes
        if detections.Length >= 3 && span < 60.0 then
            add ScoreFactorKind.Velocity "Detection velocity" 8.0
                (sprintf "%d detections within %.0f minutes" detections.Length span) []
        ignore first
    | [] -> ()

    // --- asset criticality modifier ---
    let critWeight = Criticality.weight entity.Criticality
    if critWeight <> 1.0 && severityScore > 0.0 then
        let contrib = severityScore * (critWeight - 1.0)
        add ScoreFactorKind.AssetCriticality "Asset criticality"
            contrib (sprintf "criticality '%s' (weight %.2f)" (Criticality.label entity.Criticality) critWeight) []

    // --- threat intel confidence ---
    let tiConfidence =
        detections
        |> List.filter (fun d -> d.EngineKind = DetectionEngineKind.ThreatIntel)
        |> List.map (fun d -> d.Confidence)
        |> function [] -> 0 | xs -> List.max xs
    if tiConfidence > 0 then
        add ScoreFactorKind.ThreatIntelConfidence "Threat intel match" (float tiConfidence * 0.3)
            "matched a known malicious indicator" []

    // --- triage suppression ---
    match entity.TriageState with
    | TriageState.ClosedBenign | TriageState.ExpectedBehavior ->
        add ScoreFactorKind.TriageSuppression "Analyst triage suppression" -40.0
            "analyst marked this entity as benign/expected" []
    | _ -> ()

    // --- time decay of the oldest activity ---
    match detections |> List.map (fun d -> d.UpdatedAt) |> function [] -> None | xs -> Some (List.max xs) with
    | Some mostRecent ->
        let ageHours = (now - mostRecent).TotalHours
        if ageHours > 24.0 then
            let decay = -(min 20.0 (ageHours / 24.0 * 5.0))
            add ScoreFactorKind.TimeDecay "Time decay" decay
                (sprintf "most recent activity %.0f hours ago" ageHours) []
    | None -> ()

    let total = factors |> List.sumBy (fun f -> f.Contribution)
    let risk = clamp total
    // urgency folds criticality/group importance on top for prioritization
    let urgency = clamp (total * critWeight)
    let threat =
        match detections with
        | [] -> 0
        | _ -> detections |> List.map (fun d -> d.ThreatScore) |> List.max
    let certainty =
        match detections with
        | [] -> 0
        | _ -> clamp (detections |> List.averageBy (fun d -> float d.Certainty))

    { EntityId = entity.EntityId
      ComputedAt = now
      Scores = { Risk = risk; Urgency = urgency; Threat = threat; Certainty = certainty }
      Factors = factors |> List.rev
      History =
        [ { At = now; Risk = risk; Urgency = urgency; Threat = threat; Certainty = certainty
            ChangeReason = "recomputed from open detections" } ] }

/// Recompute scores for every entity that has detections and persist the results.
let recomputeAll (store: AstraStore) (now: DateTimeOffset) =
    store.Entities
    |> List.iter (fun e ->
        let breakdown = computeBreakdown store now e
        store.SetScoreBreakdown breakdown
        store.UpsertEntity { e with Scores = breakdown.Scores })
