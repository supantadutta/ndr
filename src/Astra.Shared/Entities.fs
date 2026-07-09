namespace Astra.Shared

open System

[<RequireQualifiedAccess>]
type EntityType =
    | Host
    | Account
    | Domain
    | IpAddress
    | Service
    | Sensor
    | Subnet
    | Application
    | CloudIdentity
    | CloudResource
    | SaasApplication
    | ExternalDestination
    | ThreatIndicator

[<RequireQualifiedAccess>]
type Criticality =
    | Low
    | Normal
    | High
    | Critical

[<RequireQualifiedAccess>]
type TriageState =
    | Untriaged
    | InProgress
    | ClosedBenign
    | ClosedRemediated
    | ExpectedBehavior
    | Escalated

/// Compact behavioral profile: what "normal" looks like for this entity.
/// Populated and refined by the baseline engine.
type BehaviorProfile =
    { NormalProtocols: string list
      NormalPorts: int list
      NormalPeers: string list
      NormalLoginSources: string list
      NormalLoginHours: string option        // e.g. "08:00-19:00 Mon-Fri"
      NormalExternalDestinations: string list
      NormalDnsQueryRatePerHour: float option
      NormalByteVolumePerDay: int64 option }

type EntityScores =
    { Risk: int          // 0-100
      Urgency: int       // 0-100 unified prioritization score
      Threat: int        // 0-100
      Certainty: int }   // 0-100

type EntityProfile =
    { EntityId: EntityId
      EntityType: EntityType
      DisplayName: string
      CanonicalName: string
      KnownAliases: string list
      FirstSeen: DateTimeOffset
      LastSeen: DateTimeOffset
      LastObservedSensor: string option
      IdentityConfidence: int                // 0-100: confidence in entity resolution
      Criticality: Criticality
      BusinessUnit: string option
      Owner: string option
      Location: string option
      Tags: string list
      GroupMemberships: string list
      IdentitySources: string list           // dhcp | dns | ad | manual | cloud ...
      Behavior: BehaviorProfile
      Scores: EntityScores
      RelatedDetectionCount: int
      RelatedIncidentCount: int
      AnalystNotes: string list
      TriageState: TriageState }

[<RequireQualifiedAccess>]
type GroupMembershipRule =
    | StaticMembers of string list
    | HostnameRegex of string
    | AccountRegex of string
    | IpCidr of string list
    | AdImported of string                  // AD group distinguished name

type EntityGroup =
    { GroupId: Guid
      Name: string
      Description: string
      EntityType: EntityType
      Rule: GroupMembershipRule
      /// Multiplier applied by the scoring engine (1.0 = neutral).
      ImportanceWeight: float
      IsCriticalAssetGroup: bool
      Tags: string list }

// ---------------------------------------------------------------------------
// Coverage configuration: internal/external classification
// ---------------------------------------------------------------------------

type CoverageConfig =
    { InternalCidrs: string list
      ExternalCidrs: string list
      ExcludedCidrs: string list
      DroppedCidrs: string list
      LabSimulationCidrs: string list
      SensorZones: string list
      DataCenterCidrs: string list
      CloudVpcCidrs: string list
      RemoteUserCidrs: string list
      VpnCidrs: string list
      OtIotCidrs: string list
      DmzCidrs: string list
      ProxyIps: string list
      DnsServerAllowlist: string list
      DomainControllers: string list
      CriticalAssets: string list
      KeySubnets: string list }

module CoverageConfig =
    let empty =
        { InternalCidrs = [ "10.0.0.0/8"; "172.16.0.0/12"; "192.168.0.0/16" ]
          ExternalCidrs = []
          ExcludedCidrs = []
          DroppedCidrs = []
          LabSimulationCidrs = []
          SensorZones = []
          DataCenterCidrs = []
          CloudVpcCidrs = []
          RemoteUserCidrs = []
          VpnCidrs = []
          OtIotCidrs = []
          DmzCidrs = []
          ProxyIps = []
          DnsServerAllowlist = []
          DomainControllers = []
          CriticalAssets = []
          KeySubnets = [] }

module EntityType =
    let label = function
        | EntityType.Host -> "host"
        | EntityType.Account -> "account"
        | EntityType.Domain -> "domain"
        | EntityType.IpAddress -> "ip_address"
        | EntityType.Service -> "service"
        | EntityType.Sensor -> "sensor"
        | EntityType.Subnet -> "subnet"
        | EntityType.Application -> "application"
        | EntityType.CloudIdentity -> "cloud_identity"
        | EntityType.CloudResource -> "cloud_resource"
        | EntityType.SaasApplication -> "saas_application"
        | EntityType.ExternalDestination -> "external_destination"
        | EntityType.ThreatIndicator -> "threat_indicator"

module Criticality =
    let weight = function
        | Criticality.Low -> 0.8
        | Criticality.Normal -> 1.0
        | Criticality.High -> 1.25
        | Criticality.Critical -> 1.5
    let label = function
        | Criticality.Low -> "low"
        | Criticality.Normal -> "normal"
        | Criticality.High -> "high"
        | Criticality.Critical -> "critical"
