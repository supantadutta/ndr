module Astra.Server.Correlation

open System
open Astra.Shared
open Astra.Server.Store

/// Correlation engine: promotes clusters of related detections on the same
/// primary entity into incidents, and classifies the attack profile from the
/// mix of detection categories present.

let private classifyProfile (categories: DetectionCategory Set) : AttackProfile =
    let has c = Set.contains c categories
    if has DetectionCategory.CommandAndControl && has DetectionCategory.LateralMovement && has DetectionCategory.Exfiltration then
        AttackProfile.IntrusionWithExfiltration
    elif has DetectionCategory.LateralMovement && has DetectionCategory.MalwareBehavior then
        AttackProfile.RansomwareStaging
    elif has DetectionCategory.CommandAndControl && (has DetectionCategory.Reconnaissance || has DetectionCategory.LateralMovement) then
        AttackProfile.ActiveIntrusion
    elif has DetectionCategory.CredentialAttack && has DetectionCategory.LateralMovement then
        AttackProfile.CompromisedAccount
    elif has DetectionCategory.CommandAndControl then
        AttackProfile.SuspectedC2
    elif has DetectionCategory.CredentialAttack then
        AttackProfile.CompromisedAccount
    elif has DetectionCategory.CloudSaas then
        AttackProfile.CloudCompromise
    elif has DetectionCategory.PolicyExposure then
        AttackProfile.PolicyViolation
    else AttackProfile.Unclassified

let private containmentFor = function
    | AttackProfile.IntrusionWithExfiltration ->
        [ "Isolate the primary host"; "Block the exfiltration destination"; "Preserve volatile evidence"; "Rotate exposed credentials" ]
    | AttackProfile.RansomwareStaging ->
        [ "Isolate affected hosts immediately"; "Disable the abused account"; "Block lateral SMB paths"; "Verify backup integrity" ]
    | AttackProfile.ActiveIntrusion ->
        [ "Isolate the primary host"; "Block C2 infrastructure"; "Hunt for additional footholds" ]
    | AttackProfile.CompromisedAccount ->
        [ "Disable or reset the account"; "Review recent account activity"; "Check for persistence" ]
    | AttackProfile.SuspectedC2 ->
        [ "Block the C2 destination"; "Isolate the host if corroborated" ]
    | AttackProfile.CloudCompromise ->
        [ "Revoke suspicious cloud sessions/keys"; "Review IAM changes"; "Enable additional cloud logging" ]
    | _ -> [ "Investigate and validate before containment" ]

/// Build/refresh incidents from open detections. Returns newly created incidents.
let correlate (store: AstraStore) (now: DateTimeOffset) : Incident list =
    let openDetections = store.Detections |> List.filter (fun d -> d.Status = "open")

    openDetections
    |> List.groupBy (fun d -> d.AffectedEntity)
    |> List.choose (fun (entityId, detections) ->
        // Require either 2+ categories or a single Critical detection to raise an incident.
        let categories = detections |> List.map (fun d -> d.Category) |> Set.ofList
        let hasCritical = detections |> List.exists (fun d -> d.Severity = Severity.Critical)
        if categories.Count < 2 && not hasCritical then None
        else
            let existing =
                store.Incidents
                |> List.tryFind (fun i -> i.PrimaryEntity = entityId && i.Status <> IncidentStatus.Closed)
            match existing with
            | Some _ -> None   // already tracked; refresh handled elsewhere in later phases
            | None ->
                let entity = store.TryGetEntity entityId
                let primaryName = entity |> Option.map (fun e -> e.DisplayName) |> Option.defaultValue "unknown"
                let profile = classifyProfile categories
                let severity =
                    detections |> List.map (fun d -> Severity.toInt d.Severity) |> List.max |> fun v ->
                        if v >= 100 then Severity.Critical elif v >= 75 then Severity.High
                        elif v >= 50 then Severity.Medium elif v >= 25 then Severity.Low else Severity.Info
                let affected =
                    detections
                    |> List.collect (fun d -> d.AffectedEntity :: d.RelatedEntities)
                    |> List.distinct
                let timeline =
                    detections
                    |> List.sortBy (fun d -> d.CreatedAt)
                    |> List.map (fun d ->
                        { At = d.CreatedAt; Stage = d.KillChainStage
                          Description = d.Title; DetectionId = Some d.DetectionId })
                let urgency =
                    entity |> Option.map (fun e -> e.Scores.Urgency)
                    |> Option.defaultValue (detections |> List.map (fun d -> d.UrgencyContribution) |> List.max)
                let incident =
                    { IncidentId = IncidentId(Guid.NewGuid())
                      Title = sprintf "%A on %s" profile primaryName
                      Summary = sprintf "%d correlated detections across %d categories on %s." detections.Length categories.Count primaryName
                      AffectedEntities = affected
                      PrimaryEntity = entityId
                      Severity = severity
                      Confidence = detections |> List.averageBy (fun d -> float d.Confidence) |> int
                      Urgency = urgency
                      KillChainStage =
                        detections |> List.maxBy (fun d -> KillChainStage.ordinal d.KillChainStage) |> fun d -> d.KillChainStage
                      AttackProfile = profile
                      Timeline = timeline
                      RelatedDetections = detections |> List.map (fun d -> d.DetectionId)
                      BlastRadiusEntityCount = affected.Length
                      RecommendedContainment = containmentFor profile
                      RecommendedInvestigation =
                        [ "Review the correlated detection timeline"
                          "Confirm the primary entity's role and criticality"
                          "Expand the attack graph to find additional affected entities" ]
                      AnalystNotes = []
                      Status = IncidentStatus.New
                      Owner = None
                      SlaDeadline = Some (now.AddHours 4.0)
                      CreatedAt = now
                      UpdatedAt = now
                      ExportedToSiem = false
                      ExportedToTicketing = false }
                store.AddIncident incident
                entity |> Option.iter (fun e ->
                    store.UpsertEntity { e with RelatedIncidentCount = e.RelatedIncidentCount + 1 })
                Some incident)
