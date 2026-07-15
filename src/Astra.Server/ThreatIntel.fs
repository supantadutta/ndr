module Astra.Server.ThreatIntel

open System
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Threat-intelligence matching. Scans the recent event window for destinations
/// / domains that match an enabled indicator and raises an evidence-bound
/// ThreatIntel detection (deduped per rule+entity), recording the match.
/// ============================================================================

let private ruleId = RuleId "intel.indicator_match"

/// Extract candidate (type, value) indicators observed in an event.
let private candidates (e: NormalizedEvent) : (IndicatorType * string) list =
    let ipCand =
        if e.Direction = TrafficDirection.InternalToExternal then [ IndicatorType.Ip, e.DestinationIp ] else []
    let appCand =
        match e.Payload with
        | EventPayload.Dns d when d.Query <> "" -> [ IndicatorType.Domain, d.Query ]
        | EventPayload.Tls t -> (match t.Sni with Some s -> [ IndicatorType.Domain, s ] | None -> [])
        | EventPayload.Http h when h.Host <> "" -> [ IndicatorType.Domain, h.Host ]
        | EventPayload.FileMetadata f -> (match f.Sha256 with Some h -> [ IndicatorType.Hash, h ] | None -> [])
        | _ -> []
    ipCand @ appCand

let private mkDetection (now: DateTimeOffset) (affected: EntityProfile) (ind: ThreatIndicator) (evts: NormalizedEvent list) : Detection =
    let conf = ind.Confidence
    let sev = if conf >= 80 then Severity.Critical elif conf >= 50 then Severity.High else Severity.Medium
    { DetectionId = DetectionId(Guid.NewGuid())
      EngineKind = DetectionEngineKind.ThreatIntel
      RuleId = ruleId
      Title = sprintf "Threat intel match: %s (%s)" ind.Indicator (IndicatorType.label ind.IndicatorType)
      Summary =
        sprintf "%s contacted known-malicious %s '%s' from feed '%s'%s (confidence %d%%)."
            affected.DisplayName (IndicatorType.label ind.IndicatorType) ind.Indicator ind.FeedName
            (match ind.ActorLabel with Some a -> sprintf " attributed to %s" a | None -> "") conf
      Description = "An observed destination or domain matched a threat-intelligence indicator."
      Category = DetectionCategory.CommandAndControl
      Tactic = MitreTactic.CommandAndControl
      TechniqueId = "T1071"; TechniqueName = "Application Layer Protocol"
      KillChainStage = KillChainStage.CommandAndControl
      Severity = sev; Confidence = conf; Certainty = conf
      ThreatScore = min 100 (conf + 10)
      UrgencyContribution = min 100 (conf + 10)
      AffectedEntity = affected.EntityId
      SourceEntity = Some affected.EntityId; TargetEntity = None; RelatedEntities = []
      Evidence =
        [ { Label = "indicator"; Value = ind.Indicator; EventIds = evts |> List.truncate 20 |> List.map (fun e -> e.EventId) }
          { Label = "indicator type"; Value = IndicatorType.label ind.IndicatorType; EventIds = [] }
          { Label = "feed"; Value = ind.FeedName; EventIds = [] }
          { Label = "confidence"; Value = sprintf "%d%%" conf; EventIds = [] }
          match ind.ActorLabel with Some a -> { Label = "actor"; Value = a; EventIds = [] } | None -> () ]
      EvidenceReferences = evts |> List.truncate 20 |> List.choose (fun e -> e.RawEventReference)
      EventIds = evts |> List.truncate 200 |> List.map (fun e -> e.EventId)
      TimelineStart = (evts |> List.map (fun e -> e.Timestamp) |> List.min)
      TimelineEnd = (evts |> List.map (fun e -> e.Timestamp) |> List.max)
      BaselineComparisons = []
      WhySuspicious = "Communication with infrastructure on a curated threat-intel feed is a high-fidelity indicator of compromise, especially with actor/campaign attribution."
      FalsePositiveConsiderations = [ "Stale indicators past their useful life"; "Shared hosting where the IOC no longer resolves to the malicious tenant" ]
      RecommendedInvestigationSteps =
        [ "Confirm the indicator is current and the attribution is credible"
          "Review what the host did before and after the contact"
          "Check whether other internal hosts contacted the same indicator" ]
      RecommendedResponseActions = [ "Block the indicator (requires approval)"; "Isolate the host (simulation) if corroborated" ]
      TuningFields = Map.ofList [ "indicator", ind.Indicator; "detection_type", "intel.indicator_match" ]
      TriageState = TriageState.Untriaged; AssignedOwner = None; Status = "open"
      CreatedAt = now; UpdatedAt = now }

/// Scan the window, produce detections + record matches. Returns new detections.
let scan (store: AstraStore) (window: NormalizedEvent list) (now: DateTimeOffset) : Detection list =
    if store.Indicators.IsEmpty then []
    else
        window
        |> List.collect (fun e -> candidates e |> List.choose (fun (t, v) -> store.TryMatchIndicator(t, v) |> Option.map (fun ind -> e, ind, v)))
        |> List.groupBy (fun (_, ind, _) -> ind.Indicator)
        |> List.choose (fun (_, hits) ->
            let (firstEvt, ind, matchedValue) = List.head hits
            let evts = hits |> List.map (fun (e, _, _) -> e)
            let srcIp = firstEvt.SourceIp
            let affected = store.ResolveEntity(EntityType.Host, srcIp, srcIp, now)
            if store.HasOpenDetection(ruleId, affected.EntityId) then None
            else
                let d = mkDetection now affected ind evts
                store.AddDetection d
                (match store.TryGetEntity affected.EntityId with
                 | Some ent -> store.UpsertEntity { ent with RelatedDetectionCount = ent.RelatedDetectionCount + 1 }
                 | None -> ())
                store.RecordIntelMatch
                    { MatchId = Guid.NewGuid(); Indicator = ind.Indicator; IndicatorType = ind.IndicatorType
                      FeedName = ind.FeedName; ActorLabel = ind.ActorLabel
                      MatchedEntity = Some affected.EntityId; MatchedValue = matchedValue
                      MatchedAt = now; DetectionId = Some d.DetectionId }
                Some d)

// ---------------------------------------------------------------------------
// Import helpers
// ---------------------------------------------------------------------------

/// Parse CSV text: indicator,type,feed,confidence[,actor][,tool][,campaign]
let importCsv (store: AstraStore) (feedName: string) (text: string) : int =
    let now = DateTimeOffset.UtcNow
    text.Replace("\r\n", "\n").Split('\n')
    |> Array.filter (fun l -> l.Trim() <> "" && not (l.StartsWith "#") && not (l.StartsWith "indicator,"))
    |> Array.fold (fun count line ->
        let cols = line.Split(',') |> Array.map (fun c -> c.Trim())
        if cols.Length < 2 then count
        else
            let confidence = if cols.Length > 3 then (match Int32.TryParse cols.[3] with true, n -> n | _ -> 50) else 50
            let opt i = if cols.Length > i && cols.[i] <> "" then Some cols.[i] else None
            store.UpsertIndicator
                { IndicatorId = Guid.NewGuid()
                  Indicator = cols.[0]
                  IndicatorType = IndicatorType.parse cols.[1]
                  FeedName = (if cols.Length > 2 && cols.[2] <> "" then cols.[2] else feedName)
                  ActorLabel = opt 4; ToolLabel = opt 5; CampaignLabel = opt 6
                  Confidence = confidence; FirstSeen = now; LastSeen = now; ExpiresAt = None; Enabled = true }
            count + 1) 0
