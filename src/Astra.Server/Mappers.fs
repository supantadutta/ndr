module Astra.Server.Mappers

open System
open Astra.Shared
open Astra.Shared.Api
open Astra.Server.Store

let private iso (d: DateTimeOffset) = d.ToString("o")
let private eidStr (EntityId g) = string g
let private didStr (DetectionId g) = string g
let private iidStr (IncidentId g) = string g

let entityName (store: AstraStore) (id: EntityId) =
    store.TryGetEntity id |> Option.map (fun e -> e.DisplayName) |> Option.defaultValue (eidStr id)

// ------------------------------------------------------------------ dashboard
let dashboardSummary (store: AstraStore) : DashboardSummaryDto =
    let detections = store.Detections
    let openDet = detections |> List.filter (fun d -> d.Status = "open")
    let sensors = store.Sensors
    let now = DateTimeOffset.UtcNow

    let tacticDist =
        openDet
        |> List.groupBy (fun d -> d.Tactic)
        |> List.map (fun (t, ds) -> { Tactic = MitreTactic.label t; Count = ds.Length })
        |> List.sortByDescending (fun x -> x.Count)

    let trend =
        [ for h in 0 .. 11 ->
            let bucketEnd = now.AddHours(float (-h))
            let bucketStart = bucketEnd.AddHours(-1.0)
            let inBucket = openDet |> List.filter (fun d -> d.CreatedAt >= bucketStart && d.CreatedAt < bucketEnd)
            { BucketStart = iso bucketStart
              Count = inBucket.Length
              CriticalCount = inBucket |> List.filter (fun d -> d.Severity = Severity.Critical) |> List.length } ]
        |> List.rev

    let onlineCount = sensors |> List.filter (fun s -> s.Status = SensorStatus.Online) |> List.length
    let prioritized = store.Entities |> List.filter (fun e -> e.Scores.Urgency > 0) |> List.length

    { ActiveIncidents = store.Incidents |> List.filter (fun i -> i.Status <> IncidentStatus.Closed) |> List.length
      OpenDetections = openDet.Length
      CriticalDetections = openDet |> List.filter (fun d -> d.Severity = Severity.Critical) |> List.length
      PrioritizedEntities = prioritized
      SensorsOnline = onlineCount
      SensorsTotal = sensors.Length
      EventsLast24h = store.EventCount
      MeanTimeToTriageMinutes = 0.0
      TacticDistribution = tacticDist
      DetectionTrend = trend }

// ------------------------------------------------------------------- entities
let entityQueueItem (store: AstraStore) (e: EntityProfile) : EntityQueueItemDto =
    let importance =
        e.GroupMemberships
        |> List.length
        |> fun n -> 1.0 + float n * 0.1
    { EntityId = eidStr e.EntityId
      EntityType = EntityType.label e.EntityType
      DisplayName = e.DisplayName
      Urgency = e.Scores.Urgency
      Risk = e.Scores.Risk
      Threat = e.Scores.Threat
      Certainty = e.Scores.Certainty
      DetectionCount = e.RelatedDetectionCount
      IncidentCount = e.RelatedIncidentCount
      LastSeen = iso e.LastSeen
      Criticality = Criticality.label e.Criticality
      GroupImportance = importance
      TriageState =
        (match e.TriageState with
         | TriageState.Untriaged -> "untriaged" | TriageState.InProgress -> "in_progress"
         | TriageState.ClosedBenign -> "closed_benign" | TriageState.ClosedRemediated -> "closed_remediated"
         | TriageState.ExpectedBehavior -> "expected_behavior" | TriageState.Escalated -> "escalated")
      Owner = e.Owner }

let entityQueue (store: AstraStore) (page: int) (pageSize: int) : EntityQueuePageDto =
    let ranked =
        store.Entities
        |> List.filter (fun e -> e.Scores.Urgency > 0)
        |> List.sortByDescending (fun e -> e.Scores.Urgency)
    let total = ranked.Length
    let items =
        ranked
        |> List.skip (min ranked.Length ((page - 1) * pageSize))
        |> List.truncate pageSize
        |> List.map (entityQueueItem store)
    { Items = items; Total = total; Page = page; PageSize = pageSize }

let entityDetail (store: AstraStore) (e: EntityProfile) : EntityDetailDto =
    let factors =
        store.TryGetScoreBreakdown e.EntityId
        |> Option.map (fun b ->
            b.Factors |> List.map (fun f ->
                { Kind = ScoreFactorKind.label f.Kind; Label = f.Label
                  Contribution = Math.Round(f.Contribution, 1); Explanation = f.Explanation }))
        |> Option.defaultValue []
    let recentDetections =
        store.Detections
        |> List.filter (fun d -> d.AffectedEntity = e.EntityId)
        |> List.sortByDescending (fun d -> d.CreatedAt)
        |> List.truncate 25
        |> List.map (fun d -> didStr d.DetectionId)
    { EntityId = eidStr e.EntityId
      EntityType = EntityType.label e.EntityType
      DisplayName = e.DisplayName
      CanonicalName = e.CanonicalName
      Aliases = e.KnownAliases
      FirstSeen = iso e.FirstSeen
      LastSeen = iso e.LastSeen
      Criticality = Criticality.label e.Criticality
      Tags = e.Tags
      Groups = e.GroupMemberships
      Urgency = e.Scores.Urgency
      Risk = e.Scores.Risk
      Threat = e.Scores.Threat
      Certainty = e.Scores.Certainty
      ScoreFactors = factors
      RecentDetectionIds = recentDetections
      TriageState = (entityQueueItem store e).TriageState }

// ----------------------------------------------------------------- detections
let private triageLabel = function
    | TriageState.Untriaged -> "untriaged" | TriageState.InProgress -> "in_progress"
    | TriageState.ClosedBenign -> "closed_benign" | TriageState.ClosedRemediated -> "closed_remediated"
    | TriageState.ExpectedBehavior -> "expected_behavior" | TriageState.Escalated -> "escalated"

let detectionListItem (store: AstraStore) (d: Detection) : DetectionListItemDto =
    { DetectionId = didStr d.DetectionId
      Title = d.Title
      Category = DetectionCategory.label d.Category
      Tactic = MitreTactic.label d.Tactic
      TechniqueId = d.TechniqueId
      TechniqueName = d.TechniqueName
      Severity = Severity.label d.Severity
      Confidence = d.Confidence
      Certainty = d.Certainty
      ThreatScore = d.ThreatScore
      AffectedEntityId = eidStr d.AffectedEntity
      AffectedEntityName = entityName store d.AffectedEntity
      TriageState = triageLabel d.TriageState
      Status = d.Status
      CreatedAt = iso d.CreatedAt }

let detectionPage (store: AstraStore) (page: int) (pageSize: int) : DetectionPageDto =
    let ordered =
        store.Detections
        |> List.sortByDescending (fun d -> d.ThreatScore, d.CreatedAt.UtcTicks)
    let total = ordered.Length
    let items =
        ordered
        |> List.skip (min ordered.Length ((page - 1) * pageSize))
        |> List.truncate pageSize
        |> List.map (detectionListItem store)
    { Items = items; Total = total; Page = page; PageSize = pageSize }

let detectionDetail (store: AstraStore) (d: Detection) : DetectionDetailDto =
    { DetectionId = didStr d.DetectionId
      RuleId = (let (RuleId r) = d.RuleId in r)
      EngineKind = string d.EngineKind
      Title = d.Title
      Summary = d.Summary
      Description = d.Description
      Category = DetectionCategory.label d.Category
      Tactic = MitreTactic.label d.Tactic
      TechniqueId = d.TechniqueId
      TechniqueName = d.TechniqueName
      KillChainStage = KillChainStage.label d.KillChainStage
      Severity = Severity.label d.Severity
      Confidence = d.Confidence
      Certainty = d.Certainty
      ThreatScore = d.ThreatScore
      AffectedEntityId = eidStr d.AffectedEntity
      AffectedEntityName = entityName store d.AffectedEntity
      Evidence = d.Evidence |> List.map (fun ev -> { Label = ev.Label; Value = ev.Value })
      EventIds = d.EventIds |> List.map (fun (EventId g) -> string g)
      TimelineStart = iso d.TimelineStart
      TimelineEnd = iso d.TimelineEnd
      WhySuspicious = d.WhySuspicious
      FalsePositiveConsiderations = d.FalsePositiveConsiderations
      RecommendedInvestigationSteps = d.RecommendedInvestigationSteps
      RecommendedResponseActions = d.RecommendedResponseActions
      TriageState = triageLabel d.TriageState
      Status = d.Status
      CreatedAt = iso d.CreatedAt }

// -------------------------------------------------------------------- sensors
let sensorHealth (store: AstraStore) (s: Sensor) : SensorHealthDto =
    let h = store.TryGetHealth s.SensorId
    { SensorId = (let (SensorId g) = s.SensorId in string g)
      Name = s.Name
      Zone = s.Zone
      Status = SensorStatus.label s.Status
      Version = s.Version
      Mode = string s.Mode
      LastHeartbeat = s.LastHeartbeat |> Option.map iso
      CpuPercent = h |> Option.map (fun x -> x.CpuPercent) |> Option.defaultValue 0.0
      MemoryPercent = h |> Option.map (fun x -> x.MemoryPercent) |> Option.defaultValue 0.0
      DiskPercent = h |> Option.map (fun x -> x.DiskPercent) |> Option.defaultValue 0.0
      PacketDropPercent = h |> Option.map (fun x -> x.PacketDropPercent) |> Option.defaultValue 0.0
      EventsPerSecond = h |> Option.map (fun x -> x.EventsPerSecond) |> Option.defaultValue 0.0
      InterfaceUp = h |> Option.map (fun x -> x.InterfaceUp) |> Option.defaultValue false
      ZeekRunning = h |> Option.map (fun x -> x.ZeekRunning) |> Option.defaultValue false
      SuricataRunning = h |> Option.map (fun x -> x.SuricataRunning) |> Option.defaultValue false
      Errors = h |> Option.map (fun x -> x.Errors) |> Option.defaultValue [] }

// ---------------------------------------------------------- detection engineering
let ruleDto (store: AstraStore) (d: DetectionRuleDef) : DetectionRuleDto =
    let (RuleId rid) = d.RuleId
    let openCount =
        store.Detections
        |> List.filter (fun det -> det.RuleId = d.RuleId && det.Status = "open")
        |> List.length
    { RuleId = rid
      Name = d.Name
      Description = d.Description
      EngineKind = string d.EngineKind
      Category = DetectionCategory.label d.Category
      Tactic = MitreTactic.label d.Tactic
      TechniqueId = d.TechniqueId
      TechniqueName = d.TechniqueName
      DefaultSeverity = Severity.label d.DefaultSeverity
      DefaultConfidence = d.DefaultConfidence
      Enabled = d.Enabled
      Thresholds = d.Thresholds |> Map.toList |> List.map (fun (k, v) -> { Key = k; Value = v })
      Version = d.Version
      OpenDetections = openCount }

let triageFilterDto (f: TriageFilter) : TriageFilterDto =
    { FilterId = string f.FilterId
      Name = f.Name
      Description = f.Description
      Conditions = f.Conditions |> List.map (fun (k, _) -> { Key = k; Value = 0.0 })
      ConditionPairs = f.Conditions
      Action = TriageAction.label f.Action
      CreatedBy = f.CreatedBy
      CreatedAt = iso f.CreatedAt
      Enabled = f.Enabled }

let allowlistDto (a: AllowlistEntry) : AllowlistDto =
    { AllowlistId = string a.AllowlistId
      Name = a.Name
      Kind = AllowlistKind.label a.Kind
      Value = a.Value
      Reason = a.Reason
      CreatedBy = a.CreatedBy
      CreatedAt = iso a.CreatedAt
      Enabled = a.Enabled }

let auditDto (e: AuditEntry) : AuditEntryDto =
    { At = iso e.At
      Actor = e.Actor
      ActorKind = e.ActorKind
      Action = e.Action
      SubjectKind = e.SubjectKind
      SubjectId = e.SubjectId }

// ------------------------------------------------------------------ incidents
let incidentListItem (store: AstraStore) (i: Incident) : IncidentListItemDto =
    { IncidentId = iidStr i.IncidentId
      Title = i.Title
      Severity = Severity.label i.Severity
      Urgency = i.Urgency
      AttackProfile = string i.AttackProfile
      Status = IncidentStatus.label i.Status
      PrimaryEntityName = entityName store i.PrimaryEntity
      AffectedEntityCount = i.AffectedEntities.Length
      DetectionCount = i.RelatedDetections.Length
      CreatedAt = iso i.CreatedAt }

// ---------------------------------------------------------------- graph (P4)
let graphNodeDto (n: GraphNode) : GraphNodeDto =
    { NodeId = n.NodeId
      Kind = (match n.Kind with
              | GraphNodeKind.Host -> "host" | GraphNodeKind.Account -> "account"
              | GraphNodeKind.Domain -> "domain" | GraphNodeKind.Ip -> "ip"
              | GraphNodeKind.Sensor -> "sensor" | GraphNodeKind.Detection -> "detection"
              | GraphNodeKind.Incident -> "incident" | GraphNodeKind.Service -> "service"
              | GraphNodeKind.CloudResource -> "cloud_resource" | GraphNodeKind.SaasObject -> "saas_object"
              | GraphNodeKind.ThreatIndicator -> "threat_indicator")
      Label = n.Label
      EntityId = n.EntityId |> Option.map (fun (EntityId g) -> string g)
      Risk = n.Risk
      Tags = n.Tags }

let graphEdgeDto (e: GraphEdge) : GraphEdgeDto =
    { EdgeId = e.EdgeId; FromNode = e.FromNode; ToNode = e.ToNode
      Kind = (string e.Kind); Label = e.Label; Weight = e.Weight }

let investigationGraphDto (g: InvestigationGraph) : InvestigationGraphDto =
    { Nodes = g.Nodes |> List.map graphNodeDto
      Edges = g.Edges |> List.map graphEdgeDto }

// ----------------------------------------------------------------- hunt (P4)
let huntRowDto (r: Astra.Server.Hunt.HuntRow) : HuntRowDto =
    { Timestamp = iso r.Timestamp; Category = r.Category; Protocol = r.Protocol; App = r.App
      SourceIp = r.SourceIp; DestinationIp = r.DestinationIp; DestinationPort = r.DestinationPort
      BytesOut = r.BytesOut; BytesIn = r.BytesIn; Detail = r.Detail }

let huntBucketDto (b: Astra.Server.Hunt.HuntAggBucket) : HuntBucketDto =
    { Key = b.Key; Count = b.Count; Bytes = b.Bytes }

let huntResultDto (r: Astra.Server.Hunt.HuntResult) : HuntResultDto =
    { Total = r.Total
      Rows = r.Rows |> List.map huntRowDto
      TopDestinations = r.TopDestinations |> List.map huntBucketDto
      TopSources = r.TopSources |> List.map huntBucketDto }

let huntQueryOfDto (q: HuntQueryDto) : Astra.Server.Hunt.HuntQuery =
    { Predicates = q.Predicates |> List.map (fun p -> { Astra.Server.Hunt.Field = p.Field; Astra.Server.Hunt.Op = p.Op; Astra.Server.Hunt.Value = p.Value })
      WindowMinutes = q.WindowMinutes
      Limit = q.Limit }

let huntQueryDto (q: Astra.Server.Hunt.HuntQuery) : HuntQueryDto =
    { Predicates = q.Predicates |> List.map (fun p -> { Field = p.Field; Op = p.Op; Value = p.Value })
      WindowMinutes = q.WindowMinutes; Limit = q.Limit }

let huntTemplateDto (t: Astra.Server.Hunt.HuntTemplate) : HuntTemplateDto =
    { Id = t.Id; Name = t.Name; Description = t.Description; Query = huntQueryDto t.Query }
