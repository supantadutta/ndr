namespace Astra.Shared

open System

/// Triage governance: filters, allowlists, and the audit trail. These control
/// what the scoring engine suppresses and record every analyst action.

[<RequireQualifiedAccess>]
type TriageAction =
    | SuppressScoring     // keep visibility, remove scoring impact
    | Hide                // remove from queues entirely
    | Tag                 // annotate only

/// A condition a triage filter matches on. Kept as (field, value) pairs against
/// a detection's TuningFields so filters are explainable and auditable.
type TriageFilter =
    { FilterId: Guid
      Name: string
      Description: string
      /// All conditions must match (AND). Field names come from a detection's tuning fields.
      Conditions: (string * string) list
      Action: TriageAction
      CreatedBy: string
      CreatedAt: DateTimeOffset
      Enabled: bool }

[<RequireQualifiedAccess>]
type AllowlistKind =
    | Ip | Cidr | Domain | Account | Port | Protocol | Sensor | Other of string

type AllowlistEntry =
    { AllowlistId: Guid
      Name: string
      Kind: AllowlistKind
      Value: string
      Reason: string
      CreatedBy: string
      CreatedAt: DateTimeOffset
      ExpiresAt: DateTimeOffset option
      Enabled: bool }

type AuditEntry =
    { At: DateTimeOffset
      Actor: string
      ActorKind: string          // user | api_key | system
      Action: string             // e.g. triage.close_benign, rule.disable
      SubjectKind: string        // detection | entity | rule | filter | allowlist
      SubjectId: string
      Details: Map<string, string> }

module TriageFilter =
    /// Does this filter match a detection's tuning fields?
    let matches (filter: TriageFilter) (tuningFields: Map<string, string>) =
        filter.Enabled
        && not filter.Conditions.IsEmpty
        && filter.Conditions |> List.forall (fun (k, v) ->
            match Map.tryFind k tuningFields with
            | Some actual -> actual = v
            | None -> false)

module TriageAction =
    let label = function
        | TriageAction.SuppressScoring -> "suppress_scoring"
        | TriageAction.Hide -> "hide"
        | TriageAction.Tag -> "tag"

module AllowlistKind =
    let label = function
        | AllowlistKind.Ip -> "ip" | AllowlistKind.Cidr -> "cidr" | AllowlistKind.Domain -> "domain"
        | AllowlistKind.Account -> "account" | AllowlistKind.Port -> "port"
        | AllowlistKind.Protocol -> "protocol" | AllowlistKind.Sensor -> "sensor"
        | AllowlistKind.Other s -> s
