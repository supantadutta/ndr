namespace Astra.Shared.Api

/// ============================================================================
/// Wire-level DTOs shared by the Fable client and the Giraffe backend.
///
/// DESIGN RULE: DTOs use only primitives, lists and records — no DUs, no
/// DateTimeOffset. Dates travel as ISO-8601 strings, enums as their canonical
/// string labels. This keeps System.Text.Json (server) and Thoth.Json (client)
/// perfectly interoperable with zero custom converters.
/// ============================================================================

type ApiError =
    { Error: string
      Detail: string }

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

type MitreTacticCountDto =
    { Tactic: string
      Count: int }

type DetectionTrendPointDto =
    { BucketStart: string     // ISO-8601
      Count: int
      CriticalCount: int }

type DashboardSummaryDto =
    { ActiveIncidents: int
      OpenDetections: int
      CriticalDetections: int
      PrioritizedEntities: int
      SensorsOnline: int
      SensorsTotal: int
      EventsLast24h: int64
      MeanTimeToTriageMinutes: float
      TacticDistribution: MitreTacticCountDto list
      DetectionTrend: DetectionTrendPointDto list }

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

type EntityQueueItemDto =
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

type EntityQueuePageDto =
    { Items: EntityQueueItemDto list
      Total: int
      Page: int
      PageSize: int }

type ScoreFactorDto =
    { Kind: string
      Label: string
      Contribution: float
      Explanation: string }

type EntityDetailDto =
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
      ScoreFactors: ScoreFactorDto list
      RecentDetectionIds: string list
      TriageState: string }

// ---------------------------------------------------------------------------
// Detections
// ---------------------------------------------------------------------------

type EvidenceItemDto =
    { Label: string
      Value: string }

type DetectionListItemDto =
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

type DetectionDetailDto =
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
      Evidence: EvidenceItemDto list
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

type DetectionPageDto =
    { Items: DetectionListItemDto list
      Total: int
      Page: int
      PageSize: int }

// ---------------------------------------------------------------------------
// Sensors
// ---------------------------------------------------------------------------

type SensorHealthDto =
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

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

type IncidentListItemDto =
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

// ---------------------------------------------------------------------------
// Ingestion (sensor -> central)
// ---------------------------------------------------------------------------

type IngestEventDto =
    { Timestamp: string
      ObservedTime: string
      Category: string
      Protocol: string
      ApplicationProtocol: string
      SourceIp: string
      DestinationIp: string
      SourcePort: int option
      DestinationPort: int option
      Hostname: string option
      Username: string option
      BytesIn: int64
      BytesOut: int64
      PacketsIn: int64
      PacketsOut: int64
      DurationMs: int64 option
      Fields: Map<string, string> }   // protocol-specific fields, normalized server-side

type IngestBatchRequest =
    { SensorId: string
      SensorName: string
      Events: IngestEventDto list }

type IngestBatchResponse =
    { Accepted: int
      Rejected: int
      Errors: string list }

type HeartbeatRequest =
    { SensorId: string
      SensorName: string
      Version: string
      CpuPercent: float
      MemoryPercent: float
      DiskPercent: float
      InterfaceUp: bool
      PacketDropPercent: float
      EventsPerSecond: float
      BufferedEvents: int64
      ZeekRunning: bool
      SuricataRunning: bool
      Errors: string list }

type HeartbeatResponse =
    { Acknowledged: bool
      ConfigVersion: int }

// ---------------------------------------------------------------------------
// AI SOC investigation assistant (read-only, evidence-bound)
// ---------------------------------------------------------------------------

/// A single evidence-bound statement with its citations (detection/event ids).
type AssistantStatementDto =
    { Text: string
      Citations: string list }

/// Investigation summary for an entity. Fact / inference / recommendation are
/// deliberately separated (see docs/ai-assistant-security.md). `Provider`
/// names what produced it ("deterministic" or a configured model).
type AssistantSummaryDto =
    { SubjectId: string
      SubjectName: string
      Headline: string
      Facts: AssistantStatementDto list
      Inferences: AssistantStatementDto list
      Recommendations: AssistantStatementDto list
      MitreTechniques: string list
      Confidence: int
      Uncertainty: string
      Provider: string
      GeneratedAt: string }

// ---------------------------------------------------------------------------
// Route table (single source of truth for URLs)
// ---------------------------------------------------------------------------

module Routes =
    let health = "/api/health"
    let dashboardSummary = "/api/dashboard/summary"
    let entityQueue = "/api/entities/queue"
    let entityDetail (id: string) = sprintf "/api/entities/%s" id
    let detections = "/api/detections"
    let detectionDetail (id: string) = sprintf "/api/detections/%s" id
    let incidents = "/api/incidents"
    let sensorsHealth = "/api/sensors/health"
    let ingestEvents = "/api/ingest/events"
    let ingestHeartbeat = "/api/ingest/heartbeat"
    let assistantEntity (id: string) = sprintf "/api/assistant/entity/%s" id
