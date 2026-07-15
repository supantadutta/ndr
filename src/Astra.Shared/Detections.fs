namespace Astra.Shared

open System

[<RequireQualifiedAccess>]
type DetectionEngineKind =
    | Rule
    | Statistical
    | Behavioral
    | Correlation
    | Signature
    | ThreatIntel
    | CustomQuery
    | SavedSearch
    | Simulation

[<RequireQualifiedAccess>]
type DetectionCategory =
    | Reconnaissance
    | CommandAndControl
    | LateralMovement
    | CredentialAttack
    | Exfiltration
    | MalwareBehavior
    | PolicyExposure
    | CloudSaas
    | Informational

type EvidenceItem =
    { Label: string                       // e.g. "distinct ports contacted"
      Value: string                       // e.g. "412 in 90s"
      EventIds: EventId list }            // raw events backing this observation

type BaselineComparison =
    { Metric: string                      // e.g. "dns_queries_per_hour"
      BaselineValue: string
      ObservedValue: string
      DeviationDescription: string }      // e.g. "14.2x above 30-day average"

type Detection =
    { DetectionId: DetectionId
      EngineKind: DetectionEngineKind
      RuleId: RuleId
      Title: string
      Summary: string
      Description: string
      Category: DetectionCategory
      Tactic: MitreTactic
      TechniqueId: string
      TechniqueName: string
      KillChainStage: KillChainStage
      Severity: Severity
      Confidence: int                     // 0-100
      Certainty: int                      // 0-100
      ThreatScore: int                    // 0-100
      UrgencyContribution: int            // 0-100 contribution into entity urgency
      AffectedEntity: EntityId
      SourceEntity: EntityId option
      TargetEntity: EntityId option
      RelatedEntities: EntityId list
      Evidence: EvidenceItem list
      EvidenceReferences: string list     // pointers into telemetry store / pcap
      EventIds: EventId list
      TimelineStart: DateTimeOffset
      TimelineEnd: DateTimeOffset
      BaselineComparisons: BaselineComparison list
      WhySuspicious: string
      FalsePositiveConsiderations: string list
      RecommendedInvestigationSteps: string list
      RecommendedResponseActions: string list
      TuningFields: Map<string, string>   // fields a triage filter could match on
      TriageState: TriageState
      AssignedOwner: string option
      Status: string                      // open | acknowledged | closed
      CreatedAt: DateTimeOffset
      UpdatedAt: DateTimeOffset }

/// Definition/metadata of a detection rule (the code or query behind it lives
/// in the engine; this is the tunable, versionable descriptor).
type DetectionRuleDef =
    { RuleId: RuleId
      Name: string
      Description: string
      EngineKind: DetectionEngineKind
      Category: DetectionCategory
      Tactic: MitreTactic
      TechniqueId: string
      TechniqueName: string
      KillChainStage: KillChainStage
      DefaultSeverity: Severity
      DefaultConfidence: int
      Enabled: bool
      Thresholds: Map<string, float>      // named tunable thresholds
      Version: int
      Author: string
      CreatedAt: DateTimeOffset
      UpdatedAt: DateTimeOffset }

module DetectionCategory =
    let label = function
        | DetectionCategory.Reconnaissance -> "reconnaissance"
        | DetectionCategory.CommandAndControl -> "command_and_control"
        | DetectionCategory.LateralMovement -> "lateral_movement"
        | DetectionCategory.CredentialAttack -> "credential_attack"
        | DetectionCategory.Exfiltration -> "exfiltration"
        | DetectionCategory.MalwareBehavior -> "malware_behavior"
        | DetectionCategory.PolicyExposure -> "policy_exposure"
        | DetectionCategory.CloudSaas -> "cloud_saas"
        | DetectionCategory.Informational -> "informational"
