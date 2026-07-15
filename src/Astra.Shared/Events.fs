namespace Astra.Shared

open System

/// ============================================================================
/// Astra NDR common event schema.
/// Every telemetry source (Zeek, Suricata, flow, cloud, identity, SaaS)
/// is normalized into `NormalizedEvent` + a typed protocol payload.
/// ============================================================================

[<RequireQualifiedAccess>]
type EventCategory =
    | NetworkConnection
    | Dns
    | Http
    | Tls
    | X509Certificate
    | SmbSession
    | SmbFile
    | SmbNamedPipe
    | Dcerpc
    | Rdp
    | Ssh
    | Ldap
    | Kerberos
    | Ntlm
    | Dhcp
    | Smtp
    | Ftp
    | Ntp
    | Icmp
    | VpnRemoteUser
    | Proxy
    | IdsSignatureAlert
    | IdsProtocolAlert
    | IdsDecoderEvent
    | FileMetadata
    | ThreatIntelMatch
    | CloudAudit
    | SaasAudit
    | IdentityAuthentication
    | SensorHealth
    | SystemAudit
    | Detection
    | Incident
    | ResponseAction

module EventCategory =
    let label = function
        | EventCategory.NetworkConnection -> "network_connection"
        | EventCategory.Dns -> "dns"
        | EventCategory.Http -> "http"
        | EventCategory.Tls -> "tls"
        | EventCategory.X509Certificate -> "x509_certificate"
        | EventCategory.SmbSession -> "smb_session"
        | EventCategory.SmbFile -> "smb_file"
        | EventCategory.SmbNamedPipe -> "smb_named_pipe"
        | EventCategory.Dcerpc -> "dcerpc"
        | EventCategory.Rdp -> "rdp"
        | EventCategory.Ssh -> "ssh"
        | EventCategory.Ldap -> "ldap"
        | EventCategory.Kerberos -> "kerberos"
        | EventCategory.Ntlm -> "ntlm"
        | EventCategory.Dhcp -> "dhcp"
        | EventCategory.Smtp -> "smtp"
        | EventCategory.Ftp -> "ftp"
        | EventCategory.Ntp -> "ntp"
        | EventCategory.Icmp -> "icmp"
        | EventCategory.VpnRemoteUser -> "vpn_remote_user"
        | EventCategory.Proxy -> "proxy"
        | EventCategory.IdsSignatureAlert -> "ids_signature_alert"
        | EventCategory.IdsProtocolAlert -> "ids_protocol_alert"
        | EventCategory.IdsDecoderEvent -> "ids_decoder_event"
        | EventCategory.FileMetadata -> "file_metadata"
        | EventCategory.ThreatIntelMatch -> "threat_intel_match"
        | EventCategory.CloudAudit -> "cloud_audit"
        | EventCategory.SaasAudit -> "saas_audit"
        | EventCategory.IdentityAuthentication -> "identity_authentication"
        | EventCategory.SensorHealth -> "sensor_health"
        | EventCategory.SystemAudit -> "system_audit"
        | EventCategory.Detection -> "detection"
        | EventCategory.Incident -> "incident"
        | EventCategory.ResponseAction -> "response_action"

// ---------------------------------------------------------------------------
// Typed protocol payloads (attached to the common envelope)
// ---------------------------------------------------------------------------

type DnsPayload =
    { Query: string
      QueryType: string
      ResponseCode: string
      Answers: string list
      QueryLength: int
      IsNxDomain: bool
      IsTxtQuery: bool }

type HttpPayload =
    { Method: string
      Host: string
      Uri: string
      StatusCode: int option
      UserAgent: string option
      Referrer: string option
      RequestBodyLen: int64
      ResponseBodyLen: int64
      ContentType: string option }

type TlsPayload =
    { Sni: string option
      TlsVersion: string option
      CipherSuite: string option
      CertificateSubject: string option
      CertificateIssuer: string option
      CertificateNotBefore: DateTimeOffset option
      CertificateNotAfter: DateTimeOffset option
      ClientFingerprint: string option   // JA3/JA4-style client fingerprint when available
      ServerFingerprint: string option   // JA3S/JA4S-style server fingerprint when available
      Established: bool }

type SmbPayload =
    { Share: string option
      FilePath: string option
      NamedPipe: string option
      Operation: string option           // read | write | delete | rename | open
      IsAdminShare: bool }

type DcerpcPayload =
    { InterfaceUuid: string option
      OperationNumber: int option
      OperationName: string option
      Endpoint: string option }

type AuthPayload =
    { AuthProtocol: string               // kerberos | ntlm | ldap | ssh | rdp | cloud_sso
      TargetService: string option       // e.g. Kerberos SPN
      Result: string                     // success | failure | error
      FailureReason: string option
      IsPrivileged: bool
      LogonType: string option }

type DhcpPayload =
    { AssignedIp: string option
      LeaseTime: int option
      ClientHostname: string option
      RequestedIp: string option }

type IdsAlertPayload =
    { SignatureId: int64
      SignatureRevision: int
      SignatureName: string
      IdsCategory: string
      IdsSeverity: int
      RuleSource: string option          // ruleset name
      PayloadSnippet: string option }

type FileMetadataPayload =
    { FileName: string option
      FileSize: int64 option
      MimeType: string option
      Md5: string option
      Sha1: string option
      Sha256: string option
      IsArchive: bool
      TransferProtocol: string option }

type CloudAuditPayload =
    { Provider: string                   // aws | azure | gcp | other
      AccountId: string option
      Region: string option
      ApiCall: string option
      ResourceId: string option
      Outcome: string option
      SourceIpAddress: string option }

type SaasAuditPayload =
    { Application: string                // m365 | gsuite | salesforce | other
      Operation: string option
      ObjectId: string option
      Workload: string option
      Outcome: string option }

type ThreatIntelMatchPayload =
    { Indicator: string
      IndicatorType: string              // ip | domain | url | hash
      FeedName: string
      ActorLabel: string option
      ToolLabel: string option
      CampaignLabel: string option
      IntelConfidence: int }

/// Discriminated union of all typed payloads. `Generic` carries category-only
/// events (flow records, ICMP, NTP, sensor health, etc.).
[<RequireQualifiedAccess>]
type EventPayload =
    | Connection
    | Dns of DnsPayload
    | Http of HttpPayload
    | Tls of TlsPayload
    | Smb of SmbPayload
    | Dcerpc of DcerpcPayload
    | Auth of AuthPayload
    | Dhcp of DhcpPayload
    | IdsAlert of IdsAlertPayload
    | FileMetadata of FileMetadataPayload
    | CloudAudit of CloudAuditPayload
    | SaasAudit of SaasAuditPayload
    | ThreatIntelMatch of ThreatIntelMatchPayload
    | Generic of Map<string, string>

// ---------------------------------------------------------------------------
// Common normalized envelope
// ---------------------------------------------------------------------------

type NormalizedEvent =
    { EventId: EventId
      Timestamp: DateTimeOffset          // when the activity happened on the wire
      ObservedTime: DateTimeOffset       // when the sensor observed/emitted it
      IngestTime: DateTimeOffset         // when the central brain accepted it
      SourceSensorId: SensorId
      SourceSensorName: string
      SourceZone: string
      CollectorType: CollectorType
      Category: EventCategory
      Protocol: Protocol
      ApplicationProtocol: AppProtocol
      SourceIp: string
      DestinationIp: string
      SourcePort: int option
      DestinationPort: int option
      SourceMac: string option
      DestinationMac: string option
      Hostname: string option
      SourceHostname: string option
      DestinationHostname: string option
      Username: string option
      AccountName: string option
      DomainName: string option
      DeviceId: string option
      AssetId: string option
      UserId: string option
      SessionId: string option
      ConnectionId: string option
      Direction: TrafficDirection
      Lane: TrafficLane
      BytesIn: int64
      BytesOut: int64
      PacketsIn: int64
      PacketsOut: int64
      DurationMs: int64 option
      Country: string option
      Asn: string option
      Payload: EventPayload
      RiskHint: int option               // 0-100 hint from the producer
      SeverityHint: Severity option
      ConfidenceHint: int option         // 0-100
      RawEventReference: string option   // pointer into raw telemetry store
      Enrichment: Map<string, string>
      Tags: string list }

module NormalizedEvent =
    /// True when either endpoint is classified as external.
    let touchesExternal (e: NormalizedEvent) =
        match e.Direction with
        | TrafficDirection.InternalToExternal
        | TrafficDirection.ExternalToInternal
        | TrafficDirection.ExternalToExternal -> true
        | _ -> false
