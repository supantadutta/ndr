namespace Astra.Shared

open System

[<RequireQualifiedAccess>]
type IncidentStatus =
    | New
    | Investigating
    | Contained
    | Remediated
    | Closed
    | FalsePositive

[<RequireQualifiedAccess>]
type AttackProfile =
    | SuspectedC2
    | ActiveIntrusion
    | CompromisedAccount
    | RansomwareStaging
    | IntrusionWithExfiltration
    | SharedC2Infrastructure
    | CloudCompromise
    | SaasAccountCompromise
    | PolicyViolation
    | Unclassified

type IncidentTimelineEntry =
    { At: DateTimeOffset
      Stage: KillChainStage
      Description: string
      DetectionId: DetectionId option }

type Incident =
    { IncidentId: IncidentId
      Title: string
      Summary: string
      AffectedEntities: EntityId list
      PrimaryEntity: EntityId
      Severity: Severity
      Confidence: int
      Urgency: int
      KillChainStage: KillChainStage
      AttackProfile: AttackProfile
      Timeline: IncidentTimelineEntry list
      RelatedDetections: DetectionId list
      BlastRadiusEntityCount: int
      RecommendedContainment: string list
      RecommendedInvestigation: string list
      AnalystNotes: string list
      Status: IncidentStatus
      Owner: string option
      SlaDeadline: DateTimeOffset option
      CreatedAt: DateTimeOffset
      UpdatedAt: DateTimeOffset
      ExportedToSiem: bool
      ExportedToTicketing: bool }

// ---------------------------------------------------------------------------
// Investigation graph
// ---------------------------------------------------------------------------

[<RequireQualifiedAccess>]
type GraphNodeKind =
    | Host
    | Account
    | Domain
    | Ip
    | Sensor
    | Detection
    | Incident
    | Service
    | CloudResource
    | SaasObject
    | ThreatIndicator

[<RequireQualifiedAccess>]
type GraphEdgeKind =
    | CommunicatedWith
    | AuthenticatedTo
    | QueriedDns
    | ConnectedTo
    | UsedProtocol
    | TriggeredDetection
    | TargetedEntity
    | SharedC2Infrastructure
    | SameAccountUsedOnHost
    | SameDomainContacted
    | SameThreatIndicator
    | SameIncidentMembership

type GraphNode =
    { NodeId: string
      Kind: GraphNodeKind
      Label: string
      EntityId: EntityId option
      Risk: int
      Tags: string list }

type GraphEdge =
    { EdgeId: string
      FromNode: string
      ToNode: string
      Kind: GraphEdgeKind
      Label: string
      FirstSeen: DateTimeOffset
      LastSeen: DateTimeOffset
      Weight: float }

type InvestigationGraph =
    { Nodes: GraphNode list
      Edges: GraphEdge list }

module IncidentStatus =
    let label = function
        | IncidentStatus.New -> "new"
        | IncidentStatus.Investigating -> "investigating"
        | IncidentStatus.Contained -> "contained"
        | IncidentStatus.Remediated -> "remediated"
        | IncidentStatus.Closed -> "closed"
        | IncidentStatus.FalsePositive -> "false_positive"
