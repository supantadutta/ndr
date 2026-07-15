namespace Astra.Shared

open System

/// Explainable scoring: every score an analyst sees can be decomposed into
/// named contributions. The UI renders these directly.

[<RequireQualifiedAccess>]
type ScoreFactorKind =
    | DetectionSeverity
    | DetectionConfidence
    | BehavioralRarity
    | CategoryBreadth          // number of distinct detection categories
    | Velocity                 // speed of detection progression
    | KillChainProgression
    | AffectedEntityBreadth
    | SharedInfrastructure
    | AssetCriticality
    | AccountPrivilege
    | GroupImportance
    | ThreatIntelConfidence
    | TriageSuppression
    | AllowlistSuppression
    | Repetition
    | TimeDecay

type ScoreFactor =
    { Kind: ScoreFactorKind
      Label: string
      /// Signed contribution in score points (negative = reduces the score).
      Contribution: float
      Explanation: string
      RelatedDetections: DetectionId list }

type ScoreSnapshot =
    { At: DateTimeOffset
      Risk: int
      Urgency: int
      Threat: int
      Certainty: int
      ChangeReason: string }

type ScoreBreakdown =
    { EntityId: EntityId
      ComputedAt: DateTimeOffset
      Scores: EntityScores
      Factors: ScoreFactor list
      History: ScoreSnapshot list }

module ScoreFactorKind =
    let label = function
        | ScoreFactorKind.DetectionSeverity -> "detection_severity"
        | ScoreFactorKind.DetectionConfidence -> "detection_confidence"
        | ScoreFactorKind.BehavioralRarity -> "behavioral_rarity"
        | ScoreFactorKind.CategoryBreadth -> "category_breadth"
        | ScoreFactorKind.Velocity -> "velocity"
        | ScoreFactorKind.KillChainProgression -> "kill_chain_progression"
        | ScoreFactorKind.AffectedEntityBreadth -> "affected_entity_breadth"
        | ScoreFactorKind.SharedInfrastructure -> "shared_infrastructure"
        | ScoreFactorKind.AssetCriticality -> "asset_criticality"
        | ScoreFactorKind.AccountPrivilege -> "account_privilege"
        | ScoreFactorKind.GroupImportance -> "group_importance"
        | ScoreFactorKind.ThreatIntelConfidence -> "threat_intel_confidence"
        | ScoreFactorKind.TriageSuppression -> "triage_suppression"
        | ScoreFactorKind.AllowlistSuppression -> "allowlist_suppression"
        | ScoreFactorKind.Repetition -> "repetition"
        | ScoreFactorKind.TimeDecay -> "time_decay"
