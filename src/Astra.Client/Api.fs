module Astra.Client.Api

open Fable.Core
open Fetch
open Thoth.Json
open Astra.Client.Types

/// Typed API client. Base URL comes from the injected global `ASTRA_API_BASE`
/// (set by Vite env), defaulting to same-origin "/api" behind a reverse proxy
/// or the dev server proxy.

[<Emit("(import.meta.env && import.meta.env.VITE_API_BASE) || ''")>]
let private apiBase : string = jsNative

let private url (path: string) = apiBase + path

// ------------------------------------------------------------------ decoders
module private Decode =
    let mitreTactic : Decoder<MitreTacticCount> =
        Decode.object (fun get ->
            { Tactic = get.Required.Field "tactic" Decode.string
              Count = get.Required.Field "count" Decode.int })

    let trendPoint : Decoder<DetectionTrendPoint> =
        Decode.object (fun get ->
            { BucketStart = get.Required.Field "bucketStart" Decode.string
              Count = get.Required.Field "count" Decode.int
              CriticalCount = get.Required.Field "criticalCount" Decode.int })

    let dashboard : Decoder<DashboardSummary> =
        Decode.object (fun get ->
            { ActiveIncidents = get.Required.Field "activeIncidents" Decode.int
              OpenDetections = get.Required.Field "openDetections" Decode.int
              CriticalDetections = get.Required.Field "criticalDetections" Decode.int
              PrioritizedEntities = get.Required.Field "prioritizedEntities" Decode.int
              SensorsOnline = get.Required.Field "sensorsOnline" Decode.int
              SensorsTotal = get.Required.Field "sensorsTotal" Decode.int
              EventsLast24h = get.Required.Field "eventsLast24h" Decode.int64
              MeanTimeToTriageMinutes = get.Required.Field "meanTimeToTriageMinutes" Decode.float
              TacticDistribution = get.Required.Field "tacticDistribution" (Decode.list mitreTactic)
              DetectionTrend = get.Required.Field "detectionTrend" (Decode.list trendPoint) })

    let entityItem : Decoder<EntityQueueItem> =
        Decode.object (fun get ->
            { EntityId = get.Required.Field "entityId" Decode.string
              EntityType = get.Required.Field "entityType" Decode.string
              DisplayName = get.Required.Field "displayName" Decode.string
              Urgency = get.Required.Field "urgency" Decode.int
              Risk = get.Required.Field "risk" Decode.int
              Threat = get.Required.Field "threat" Decode.int
              Certainty = get.Required.Field "certainty" Decode.int
              DetectionCount = get.Required.Field "detectionCount" Decode.int
              IncidentCount = get.Required.Field "incidentCount" Decode.int
              LastSeen = get.Required.Field "lastSeen" Decode.string
              Criticality = get.Required.Field "criticality" Decode.string
              GroupImportance = get.Required.Field "groupImportance" Decode.float
              TriageState = get.Required.Field "triageState" Decode.string
              Owner = get.Optional.Field "owner" Decode.string })

    let entityPage : Decoder<EntityQueuePage> =
        Decode.object (fun get ->
            { Items = get.Required.Field "items" (Decode.list entityItem)
              Total = get.Required.Field "total" Decode.int
              Page = get.Required.Field "page" Decode.int
              PageSize = get.Required.Field "pageSize" Decode.int })

    let scoreFactor : Decoder<ScoreFactor> =
        Decode.object (fun get ->
            { Kind = get.Required.Field "kind" Decode.string
              Label = get.Required.Field "label" Decode.string
              Contribution = get.Required.Field "contribution" Decode.float
              Explanation = get.Required.Field "explanation" Decode.string })

    let entityDetail : Decoder<EntityDetail> =
        Decode.object (fun get ->
            { EntityId = get.Required.Field "entityId" Decode.string
              EntityType = get.Required.Field "entityType" Decode.string
              DisplayName = get.Required.Field "displayName" Decode.string
              CanonicalName = get.Required.Field "canonicalName" Decode.string
              Aliases = get.Required.Field "aliases" (Decode.list Decode.string)
              FirstSeen = get.Required.Field "firstSeen" Decode.string
              LastSeen = get.Required.Field "lastSeen" Decode.string
              Criticality = get.Required.Field "criticality" Decode.string
              Tags = get.Required.Field "tags" (Decode.list Decode.string)
              Groups = get.Required.Field "groups" (Decode.list Decode.string)
              Urgency = get.Required.Field "urgency" Decode.int
              Risk = get.Required.Field "risk" Decode.int
              Threat = get.Required.Field "threat" Decode.int
              Certainty = get.Required.Field "certainty" Decode.int
              ScoreFactors = get.Required.Field "scoreFactors" (Decode.list scoreFactor)
              RecentDetectionIds = get.Required.Field "recentDetectionIds" (Decode.list Decode.string)
              TriageState = get.Required.Field "triageState" Decode.string })

    let detectionItem : Decoder<DetectionListItem> =
        Decode.object (fun get ->
            { DetectionId = get.Required.Field "detectionId" Decode.string
              Title = get.Required.Field "title" Decode.string
              Category = get.Required.Field "category" Decode.string
              Tactic = get.Required.Field "tactic" Decode.string
              TechniqueId = get.Required.Field "techniqueId" Decode.string
              TechniqueName = get.Required.Field "techniqueName" Decode.string
              Severity = get.Required.Field "severity" Decode.string
              Confidence = get.Required.Field "confidence" Decode.int
              Certainty = get.Required.Field "certainty" Decode.int
              ThreatScore = get.Required.Field "threatScore" Decode.int
              AffectedEntityId = get.Required.Field "affectedEntityId" Decode.string
              AffectedEntityName = get.Required.Field "affectedEntityName" Decode.string
              TriageState = get.Required.Field "triageState" Decode.string
              Status = get.Required.Field "status" Decode.string
              CreatedAt = get.Required.Field "createdAt" Decode.string })

    let detectionPage : Decoder<DetectionPage> =
        Decode.object (fun get ->
            { Items = get.Required.Field "items" (Decode.list detectionItem)
              Total = get.Required.Field "total" Decode.int
              Page = get.Required.Field "page" Decode.int
              PageSize = get.Required.Field "pageSize" Decode.int })

    let evidence : Decoder<EvidenceItem> =
        Decode.object (fun get ->
            { Label = get.Required.Field "label" Decode.string
              Value = get.Required.Field "value" Decode.string })

    let detectionDetail : Decoder<DetectionDetail> =
        Decode.object (fun get ->
            { DetectionId = get.Required.Field "detectionId" Decode.string
              RuleId = get.Required.Field "ruleId" Decode.string
              EngineKind = get.Required.Field "engineKind" Decode.string
              Title = get.Required.Field "title" Decode.string
              Summary = get.Required.Field "summary" Decode.string
              Description = get.Required.Field "description" Decode.string
              Category = get.Required.Field "category" Decode.string
              Tactic = get.Required.Field "tactic" Decode.string
              TechniqueId = get.Required.Field "techniqueId" Decode.string
              TechniqueName = get.Required.Field "techniqueName" Decode.string
              KillChainStage = get.Required.Field "killChainStage" Decode.string
              Severity = get.Required.Field "severity" Decode.string
              Confidence = get.Required.Field "confidence" Decode.int
              Certainty = get.Required.Field "certainty" Decode.int
              ThreatScore = get.Required.Field "threatScore" Decode.int
              AffectedEntityId = get.Required.Field "affectedEntityId" Decode.string
              AffectedEntityName = get.Required.Field "affectedEntityName" Decode.string
              Evidence = get.Required.Field "evidence" (Decode.list evidence)
              EventIds = get.Required.Field "eventIds" (Decode.list Decode.string)
              TimelineStart = get.Required.Field "timelineStart" Decode.string
              TimelineEnd = get.Required.Field "timelineEnd" Decode.string
              WhySuspicious = get.Required.Field "whySuspicious" Decode.string
              FalsePositiveConsiderations = get.Required.Field "falsePositiveConsiderations" (Decode.list Decode.string)
              RecommendedInvestigationSteps = get.Required.Field "recommendedInvestigationSteps" (Decode.list Decode.string)
              RecommendedResponseActions = get.Required.Field "recommendedResponseActions" (Decode.list Decode.string)
              TriageState = get.Required.Field "triageState" Decode.string
              Status = get.Required.Field "status" Decode.string
              CreatedAt = get.Required.Field "createdAt" Decode.string })

    let sensorHealth : Decoder<SensorHealth> =
        Decode.object (fun get ->
            { SensorId = get.Required.Field "sensorId" Decode.string
              Name = get.Required.Field "name" Decode.string
              Zone = get.Required.Field "zone" Decode.string
              Status = get.Required.Field "status" Decode.string
              Version = get.Required.Field "version" Decode.string
              Mode = get.Required.Field "mode" Decode.string
              LastHeartbeat = get.Optional.Field "lastHeartbeat" Decode.string
              CpuPercent = get.Required.Field "cpuPercent" Decode.float
              MemoryPercent = get.Required.Field "memoryPercent" Decode.float
              DiskPercent = get.Required.Field "diskPercent" Decode.float
              PacketDropPercent = get.Required.Field "packetDropPercent" Decode.float
              EventsPerSecond = get.Required.Field "eventsPerSecond" Decode.float
              InterfaceUp = get.Required.Field "interfaceUp" Decode.bool
              ZeekRunning = get.Required.Field "zeekRunning" Decode.bool
              SuricataRunning = get.Required.Field "suricataRunning" Decode.bool
              Errors = get.Required.Field "errors" (Decode.list Decode.string) })

    let incidentItem : Decoder<IncidentListItem> =
        Decode.object (fun get ->
            { IncidentId = get.Required.Field "incidentId" Decode.string
              Title = get.Required.Field "title" Decode.string
              Severity = get.Required.Field "severity" Decode.string
              Urgency = get.Required.Field "urgency" Decode.int
              AttackProfile = get.Required.Field "attackProfile" Decode.string
              Status = get.Required.Field "status" Decode.string
              PrimaryEntityName = get.Required.Field "primaryEntityName" Decode.string
              AffectedEntityCount = get.Required.Field "affectedEntityCount" Decode.int
              DetectionCount = get.Required.Field "detectionCount" Decode.int
              CreatedAt = get.Required.Field "createdAt" Decode.string })

// -------------------------------------------------------------------- fetch
let private getJson<'T> (path: string) (decoder: Decoder<'T>) : JS.Promise<Result<'T, string>> =
    promise {
        try
            let! response = fetch (url path) []
            let! text = response.text ()
            if response.Ok then
                return Decode.fromString decoder text
            else
                return Error (sprintf "HTTP %d: %s" response.Status text)
        with ex ->
            return Error ex.Message
    }

let getDashboard () = getJson "/api/dashboard/summary" Decode.dashboard
let getEntityQueue (page: int) = getJson (sprintf "/api/entities/queue?page=%d&pageSize=50" page) Decode.entityPage
let getEntityDetail (id: string) = getJson (sprintf "/api/entities/%s" id) Decode.entityDetail
let getDetections (page: int) = getJson (sprintf "/api/detections?page=%d&pageSize=50" page) Decode.detectionPage
let getDetectionDetail (id: string) = getJson (sprintf "/api/detections/%s" id) Decode.detectionDetail
let getIncidents () = getJson "/api/incidents" (Decode.list Decode.incidentItem)
let getSensors () = getJson "/api/sensors/health" (Decode.list Decode.sensorHealth)
