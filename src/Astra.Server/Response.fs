module Astra.Server.Response

open System
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Response orchestration. Every action is analyst-approved, auditable, and
/// simulation-first. Destructive kinds stay in simulation until a real connector
/// is explicitly enabled — the engine never performs a real block/isolate on its
/// own. Exports render detections/incidents to CEF or JSON for a SIEM/SOAR.
/// ============================================================================

let private audit (store: AstraStore) actor action actionId (details: (string * string) list) =
    store.Audit
        { At = DateTimeOffset.UtcNow; Actor = actor; ActorKind = "user"
          Action = action; SubjectKind = "response_action"; SubjectId = string actionId
          Details = Map.ofList details }

/// Create a pending response action. Destructive kinds are forced to simulation.
let request (store: AstraStore) (kind: ResponseActionKind) (target: string) (reason: string)
            (evidence: string list) (entities: EntityId list) (actor: string) : ResponseAction =
    let now = DateTimeOffset.UtcNow
    let action =
        { ActionId = Guid.NewGuid(); Kind = kind; Reason = reason; Target = target
          AffectedEntities = entities; Evidence = evidence
          RequestedBy = actor; ApprovedBy = None; ConnectorName = None
          Simulation = ResponseActionKind.isDestructive kind   // destructive => simulation until connector enabled
          Status = ResponseStatus.PendingApproval; Result = None
          CreatedAt = now; UpdatedAt = now }
    store.UpsertResponseAction action
    audit store actor (sprintf "response.request.%s" (ResponseActionKind.label kind)) action.ActionId
        [ "target", target; "reason", reason ]
    action

/// Approve and execute a pending action. Delivery is decided per connector:
/// a matching connector in live mode carries the action out for real via the
/// dispatcher; otherwise the side effect is recorded as a simulation. The
/// engine itself never enforces anything — a human approved, and a connector
/// explicitly flipped out of simulation mode is what makes delivery real.
let approveWith (dispatcher: Astra.Server.Connectors.IConnectorDispatcher option)
                (store: AstraStore) (actionId: Guid) (approver: string) : Result<ResponseAction, string> =
    match store.TryGetResponseAction actionId with
    | None -> Error "action not found"
    | Some a when a.Status <> ResponseStatus.PendingApproval -> Error "action is not pending approval"
    | Some a ->
        let now = DateTimeOffset.UtcNow
        let connector = Astra.Server.Connectors.selectConnector store a.Kind
        let liveDelivery =
            match dispatcher, connector with
            | Some d, Some c when not c.SimulationMode -> Some (d, c)
            | _ -> None
        let status, result, connectorName =
            match liveDelivery with
            | Some (d, c) ->
                match d.Deliver(c, { a with ApprovedBy = Some approver }) with
                | Ok msg -> ResponseStatus.Completed, sprintf "executed %s on '%s' via %s: %s" (ResponseActionKind.label a.Kind) a.Target c.ConnectorName msg, Some c.ConnectorName
                | Error e -> ResponseStatus.Failed, sprintf "delivery via %s failed: %s" c.ConnectorName e, Some c.ConnectorName
            | None ->
                ResponseStatus.Completed,
                sprintf "SIMULATED: would %s '%s'" (ResponseActionKind.label a.Kind) a.Target,
                (connector |> Option.map (fun c -> c.ConnectorName))
        // AddThreatIndicator has a real, safe effect even outside simulation.
        (match a.Kind with
         | ResponseActionKind.AddThreatIndicator ->
            store.UpsertIndicator
                { IndicatorId = Guid.NewGuid(); Indicator = a.Target
                  IndicatorType = (if a.Target.Contains "." && not (a.Target |> Seq.forall (fun c -> Char.IsDigit c || c = '.')) then IndicatorType.Domain else IndicatorType.Ip)
                  FeedName = "analyst"; ActorLabel = None; ToolLabel = None; CampaignLabel = None
                  Confidence = 75; FirstSeen = now; LastSeen = now; ExpiresAt = None; Enabled = true }
         | _ -> ())
        let simulated = liveDelivery.IsNone
        let updated =
            { a with Status = status; ApprovedBy = Some approver; Result = Some result
                     ConnectorName = connectorName; Simulation = simulated; UpdatedAt = now }
        store.UpsertResponseAction updated
        audit store approver (sprintf "response.approve.%s" (ResponseActionKind.label a.Kind)) actionId [ "result", result ]
        Ok updated

/// Approve without a dispatcher: always records a simulated side effect.
let approve (store: AstraStore) (actionId: Guid) (approver: string) : Result<ResponseAction, string> =
    approveWith None store actionId approver

let reject (store: AstraStore) (actionId: Guid) (approver: string) : Result<ResponseAction, string> =
    match store.TryGetResponseAction actionId with
    | None -> Error "action not found"
    | Some a ->
        let updated = { a with Status = ResponseStatus.Rejected; ApprovedBy = Some approver; UpdatedAt = DateTimeOffset.UtcNow }
        store.UpsertResponseAction updated
        audit store approver "response.reject" actionId []
        Ok updated

// ---------------------------------------------------------------------------
// Exports (SIEM/SOAR-ready rendering)
// ---------------------------------------------------------------------------

/// ArcSight-style CEF line for a detection.
let toCef (store: AstraStore) (d: Detection) : string =
    let entity = store.TryGetEntity d.AffectedEntity |> Option.map (fun e -> e.DisplayName) |> Option.defaultValue "-"
    let sev = match d.Severity with Severity.Critical -> 10 | Severity.High -> 8 | Severity.Medium -> 5 | Severity.Low -> 3 | Severity.Info -> 1
    let (RuleId rid) = d.RuleId
    let (DetectionId did) = d.DetectionId
    sprintf "CEF:0|AstraNDR|Astra|1.0|%s|%s|%d|externalId=%s cat=%s AstraTactic=%s AstraTechnique=%s dhost=%s cs1Label=confidence cs1=%d"
        rid d.Title sev (string did) (DetectionCategory.label d.Category)
        (MitreTactic.label d.Tactic) d.TechniqueId entity d.Confidence

/// Compact JSON-ready projection of a detection for SIEM/webhook export.
let toExportMap (store: AstraStore) (d: Detection) : Map<string, string> =
    let (DetectionId did) = d.DetectionId
    let entity = store.TryGetEntity d.AffectedEntity |> Option.map (fun e -> e.DisplayName) |> Option.defaultValue "-"
    Map.ofList
        [ "detection_id", string did; "title", d.Title
          "severity", Severity.label d.Severity; "confidence", string d.Confidence
          "tactic", MitreTactic.label d.Tactic; "technique", d.TechniqueId
          "entity", entity; "created_at", d.CreatedAt.ToString("o") ]

// ---------------------------------------------------------------------------
// Incident reporting
// ---------------------------------------------------------------------------

/// Render a plaintext incident report (analyst / customer handover).
let incidentReport (store: AstraStore) (inc: Incident) : string =
    let sb = Text.StringBuilder()
    let line (s: string) = sb.AppendLine s |> ignore
    line (sprintf "ASTRA NDR — INCIDENT REPORT")
    line (sprintf "==============================")
    line (sprintf "Title:        %s" inc.Title)
    line (sprintf "Severity:     %s    Urgency: %d" (Severity.label inc.Severity) inc.Urgency)
    line (sprintf "Attack profile: %A" inc.AttackProfile)
    line (sprintf "Status:       %s" (IncidentStatus.label inc.Status))
    line (sprintf "Primary:      %s" (store.TryGetEntity inc.PrimaryEntity |> Option.map (fun e -> e.DisplayName) |> Option.defaultValue "-"))
    line (sprintf "Blast radius: %d entities" inc.BlastRadiusEntityCount)
    line (sprintf "Created:      %s" (inc.CreatedAt.ToString("u")))
    line ""
    line "SUMMARY"
    line ("  " + inc.Summary)
    line ""
    line "KILL-CHAIN TIMELINE"
    for t in inc.Timeline do
        line (sprintf "  [%s] %s — %s" (t.At.ToString("HH:mm:ss")) (KillChainStage.label t.Stage) t.Description)
    line ""
    line "RELATED DETECTIONS"
    for did in inc.RelatedDetections do
        match store.TryGetDetection did with
        | Some d -> line (sprintf "  - %s (%s, %s)" d.Title (Severity.label d.Severity) (MitreTactic.label d.Tactic))
        | None -> ()
    line ""
    line "RECOMMENDED CONTAINMENT"
    for c in inc.RecommendedContainment do line ("  - " + c)
    line ""
    line "RECOMMENDED INVESTIGATION"
    for c in inc.RecommendedInvestigation do line ("  - " + c)
    sb.ToString()
