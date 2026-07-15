namespace Astra.Shared

open System

/// ============================================================================
/// Phase 5 domain: threat intelligence, response actions, and connectors.
/// ============================================================================

// ---------------------------------------------------------------------------
// Threat intelligence
// ---------------------------------------------------------------------------

[<RequireQualifiedAccess>]
type IndicatorType =
    | Ip | Domain | Url | Hash

type ThreatIndicator =
    { IndicatorId: Guid
      Indicator: string
      IndicatorType: IndicatorType
      FeedName: string
      ActorLabel: string option
      ToolLabel: string option
      CampaignLabel: string option
      Confidence: int              // 0-100
      FirstSeen: DateTimeOffset
      LastSeen: DateTimeOffset
      ExpiresAt: DateTimeOffset option
      Enabled: bool }

[<RequireQualifiedAccess>]
type FeedKind = Manual | Csv | Json | Taxii

type ThreatFeed =
    { FeedId: Guid
      Name: string
      Kind: FeedKind
      IndicatorCount: int
      LastUpdate: DateTimeOffset option
      Status: string }

/// A recorded match of an indicator against observed telemetry.
type ThreatIntelMatch =
    { MatchId: Guid
      Indicator: string
      IndicatorType: IndicatorType
      FeedName: string
      ActorLabel: string option
      MatchedEntity: EntityId option
      MatchedValue: string
      MatchedAt: DateTimeOffset
      DetectionId: DetectionId option }

module IndicatorType =
    let label = function
        | IndicatorType.Ip -> "ip" | IndicatorType.Domain -> "domain"
        | IndicatorType.Url -> "url" | IndicatorType.Hash -> "hash"
    let parse (s: string) =
        match s.ToLowerInvariant() with
        | "domain" -> IndicatorType.Domain | "url" -> IndicatorType.Url
        | "hash" -> IndicatorType.Hash | _ -> IndicatorType.Ip

// ---------------------------------------------------------------------------
// Response actions + connectors
// ---------------------------------------------------------------------------

[<RequireQualifiedAccess>]
type ResponseActionKind =
    | BlockIp | BlockDomain | BlockHost
    | IsolateHostSim | DisableAccountSim
    | CreateTicket | SendEmail | SendWebhook
    | ExportSiem | ExportSoar | AddThreatIndicator
    | AddBlocklistFeed

[<RequireQualifiedAccess>]
type ResponseStatus =
    | PendingApproval | Approved | Executing | Completed | Failed | RolledBack | Rejected

type ResponseAction =
    { ActionId: Guid
      Kind: ResponseActionKind
      Reason: string
      Target: string                 // ip / domain / host / account / entity
      AffectedEntities: EntityId list
      Evidence: string list          // detection/incident ids or evidence refs
      RequestedBy: string
      ApprovedBy: string option
      ConnectorName: string option
      Simulation: bool               // simulation mode = no real side effects
      Status: ResponseStatus
      Result: string option
      CreatedAt: DateTimeOffset
      UpdatedAt: DateTimeOffset }

[<RequireQualifiedAccess>]
type ConnectorKind =
    | Webhook | SyslogTcp | SyslogTls | Kafka | ElasticOpenSearch
    | SplunkHec | SentinelStyle | Soar | Edr | Firewall

type ResponseConnector =
    { ConnectorName: string
      Kind: ConnectorKind
      /// config references env keys, never secrets
      ConfigRef: string
      SimulationMode: bool
      Status: string }

module ResponseActionKind =
    let label = function
        | ResponseActionKind.BlockIp -> "block_ip" | ResponseActionKind.BlockDomain -> "block_domain"
        | ResponseActionKind.BlockHost -> "block_host" | ResponseActionKind.IsolateHostSim -> "isolate_host_sim"
        | ResponseActionKind.DisableAccountSim -> "disable_account_sim" | ResponseActionKind.CreateTicket -> "create_ticket"
        | ResponseActionKind.SendEmail -> "send_email" | ResponseActionKind.SendWebhook -> "send_webhook"
        | ResponseActionKind.ExportSiem -> "export_siem" | ResponseActionKind.ExportSoar -> "export_soar"
        | ResponseActionKind.AddThreatIndicator -> "add_threat_indicator" | ResponseActionKind.AddBlocklistFeed -> "add_blocklist_feed"
    let parse (s: string) =
        match s with
        | "block_ip" -> ResponseActionKind.BlockIp | "block_domain" -> ResponseActionKind.BlockDomain
        | "block_host" -> ResponseActionKind.BlockHost | "isolate_host_sim" -> ResponseActionKind.IsolateHostSim
        | "disable_account_sim" -> ResponseActionKind.DisableAccountSim | "create_ticket" -> ResponseActionKind.CreateTicket
        | "send_email" -> ResponseActionKind.SendEmail | "send_webhook" -> ResponseActionKind.SendWebhook
        | "export_siem" -> ResponseActionKind.ExportSiem | "export_soar" -> ResponseActionKind.ExportSoar
        | "add_threat_indicator" -> ResponseActionKind.AddThreatIndicator | _ -> ResponseActionKind.AddBlocklistFeed
    /// Destructive kinds always run in simulation until a real connector is enabled.
    let isDestructive = function
        | ResponseActionKind.BlockIp | ResponseActionKind.BlockDomain | ResponseActionKind.BlockHost
        | ResponseActionKind.IsolateHostSim | ResponseActionKind.DisableAccountSim | ResponseActionKind.AddBlocklistFeed -> true
        | _ -> false

module ResponseStatus =
    let label = function
        | ResponseStatus.PendingApproval -> "pending_approval" | ResponseStatus.Approved -> "approved"
        | ResponseStatus.Executing -> "executing" | ResponseStatus.Completed -> "completed"
        | ResponseStatus.Failed -> "failed" | ResponseStatus.RolledBack -> "rolled_back"
        | ResponseStatus.Rejected -> "rejected"

module ConnectorKind =
    let label = function
        | ConnectorKind.Webhook -> "webhook" | ConnectorKind.SyslogTcp -> "syslog_tcp"
        | ConnectorKind.SyslogTls -> "syslog_tls" | ConnectorKind.Kafka -> "kafka"
        | ConnectorKind.ElasticOpenSearch -> "elastic_opensearch" | ConnectorKind.SplunkHec -> "splunk_hec"
        | ConnectorKind.SentinelStyle -> "sentinel_style" | ConnectorKind.Soar -> "soar"
        | ConnectorKind.Edr -> "edr" | ConnectorKind.Firewall -> "firewall"
