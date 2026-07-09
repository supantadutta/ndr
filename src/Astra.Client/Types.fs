module Astra.Client.Types

/// Client-side view of the shared API DTOs. We redeclare lightweight records
/// here (rather than referencing the server DTOs directly) so the Thoth JSON
/// decoders stay explicit and the client has zero server-only dependencies.
/// Field names/shapes mirror Astra.Shared.Api exactly (camelCase on the wire).

type MitreTacticCount = { Tactic: string; Count: int }
type DetectionTrendPoint = { BucketStart: string; Count: int; CriticalCount: int }

type DashboardSummary =
    { ActiveIncidents: int
      OpenDetections: int
      CriticalDetections: int
      PrioritizedEntities: int
      SensorsOnline: int
      SensorsTotal: int
      EventsLast24h: int64
      MeanTimeToTriageMinutes: float
      TacticDistribution: MitreTacticCount list
      DetectionTrend: DetectionTrendPoint list }

type EntityQueueItem =
    { EntityId: string
      EntityType: string
      DisplayName: string
      Urgency: int
      Risk: int
      Threat: int
      Certainty: int
      DetectionCount: int
      IncidentCount: int
      LastSeen: string
      Criticality: string
      GroupImportance: float
      TriageState: string
      Owner: string option }

type EntityQueuePage =
    { Items: EntityQueueItem list; Total: int; Page: int; PageSize: int }

type ScoreFactor = { Kind: string; Label: string; Contribution: float; Explanation: string }

type EntityDetail =
    { EntityId: string
      EntityType: string
      DisplayName: string
      CanonicalName: string
      Aliases: string list
      FirstSeen: string
      LastSeen: string
      Criticality: string
      Tags: string list
      Groups: string list
      Urgency: int
      Risk: int
      Threat: int
      Certainty: int
      ScoreFactors: ScoreFactor list
      RecentDetectionIds: string list
      TriageState: string }

type DetectionListItem =
    { DetectionId: string
      Title: string
      Category: string
      Tactic: string
      TechniqueId: string
      TechniqueName: string
      Severity: string
      Confidence: int
      Certainty: int
      ThreatScore: int
      AffectedEntityId: string
      AffectedEntityName: string
      TriageState: string
      Status: string
      CreatedAt: string }

type DetectionPage =
    { Items: DetectionListItem list; Total: int; Page: int; PageSize: int }

type EvidenceItem = { Label: string; Value: string }

type DetectionDetail =
    { DetectionId: string
      RuleId: string
      EngineKind: string
      Title: string
      Summary: string
      Description: string
      Category: string
      Tactic: string
      TechniqueId: string
      TechniqueName: string
      KillChainStage: string
      Severity: string
      Confidence: int
      Certainty: int
      ThreatScore: int
      AffectedEntityId: string
      AffectedEntityName: string
      Evidence: EvidenceItem list
      EventIds: string list
      TimelineStart: string
      TimelineEnd: string
      WhySuspicious: string
      FalsePositiveConsiderations: string list
      RecommendedInvestigationSteps: string list
      RecommendedResponseActions: string list
      TriageState: string
      Status: string
      CreatedAt: string }

type SensorHealth =
    { SensorId: string
      Name: string
      Zone: string
      Status: string
      Version: string
      Mode: string
      LastHeartbeat: string option
      CpuPercent: float
      MemoryPercent: float
      DiskPercent: float
      PacketDropPercent: float
      EventsPerSecond: float
      InterfaceUp: bool
      ZeekRunning: bool
      SuricataRunning: bool
      Errors: string list }

type IncidentListItem =
    { IncidentId: string
      Title: string
      Severity: string
      Urgency: int
      AttackProfile: string
      Status: string
      PrimaryEntityName: string
      AffectedEntityCount: int
      DetectionCount: int
      CreatedAt: string }

type RuleThreshold = { Key: string; Value: float }

type DetectionRule =
    { RuleId: string
      Name: string
      Description: string
      EngineKind: string
      Category: string
      Tactic: string
      TechniqueId: string
      TechniqueName: string
      DefaultSeverity: string
      DefaultConfidence: int
      Enabled: bool
      Thresholds: RuleThreshold list
      Version: int
      OpenDetections: int }

type AuditEntry =
    { At: string
      Actor: string
      ActorKind: string
      Action: string
      SubjectKind: string
      SubjectId: string }

type AssistantStatement = { Text: string; Citations: string list }

type AssistantSummary =
    { SubjectId: string
      SubjectName: string
      Headline: string
      Facts: AssistantStatement list
      Inferences: AssistantStatement list
      Recommendations: AssistantStatement list
      MitreTechniques: string list
      Confidence: int
      Uncertainty: string
      Provider: string
      GeneratedAt: string }

/// Application routes (hash-based).
type Route =
    | Dashboard
    | Entities
    | EntityDetailRoute of string
    | DetectionsRoute
    | IncidentsRoute
    | Sensors
    | Hunting
    | AttackGraph
    | DetectionEngineering
    | ThreatIntel
    | ResponseCenter
    | Admin

module Route =
    let toHash = function
        | Dashboard -> "#/dashboard"
        | Entities -> "#/entities"
        | EntityDetailRoute id -> sprintf "#/entities/%s" id
        | DetectionsRoute -> "#/detections"
        | IncidentsRoute -> "#/incidents"
        | Sensors -> "#/sensors"
        | Hunting -> "#/hunting"
        | AttackGraph -> "#/attack-graph"
        | DetectionEngineering -> "#/detection-engineering"
        | ThreatIntel -> "#/threat-intel"
        | ResponseCenter -> "#/response"
        | Admin -> "#/admin"

    let parse (hash: string) =
        let clean = (hash.TrimStart('#')).Trim('/')
        let parts = clean.Split('/') |> Array.filter (fun s -> s <> "")
        match parts with
        | [||] -> Dashboard
        | [| "dashboard" |] -> Dashboard
        | [| "entities" |] -> Entities
        | [| "entities"; id |] -> EntityDetailRoute id
        | [| "detections" |] -> DetectionsRoute
        | [| "incidents" |] -> IncidentsRoute
        | [| "sensors" |] -> Sensors
        | [| "hunting" |] -> Hunting
        | [| "attack-graph" |] -> AttackGraph
        | [| "detection-engineering" |] -> DetectionEngineering
        | [| "threat-intel" |] -> ThreatIntel
        | [| "response" |] -> ResponseCenter
        | [| "admin" |] -> Admin
        | _ -> Dashboard
