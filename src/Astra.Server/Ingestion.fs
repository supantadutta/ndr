module Astra.Server.Ingestion

open System
open System.Threading
open System.Threading.Channels
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Astra.Shared
open Astra.Shared.Api
open Astra.Server.Store
open Astra.Server.Classification
open Astra.Server.DetectionEngine

/// Maps wire-level ingest DTOs into typed NormalizedEvents. Protocol-specific
/// fields arrive as a flat string map and are lifted into typed payloads here.
module Mapping =

    let private parseCategory (s: string) =
        match s with
        | "dns" -> EventCategory.Dns | "http" -> EventCategory.Http | "tls" -> EventCategory.Tls
        | "smb_file" | "smb_session" -> EventCategory.SmbFile | "smb_named_pipe" -> EventCategory.SmbNamedPipe
        | "dcerpc" -> EventCategory.Dcerpc | "rdp" -> EventCategory.Rdp | "ssh" -> EventCategory.Ssh
        | "ldap" -> EventCategory.Ldap | "kerberos" -> EventCategory.Kerberos | "ntlm" -> EventCategory.Ntlm
        | "dhcp" -> EventCategory.Dhcp | "icmp" -> EventCategory.Icmp
        | "ids_signature_alert" -> EventCategory.IdsSignatureAlert
        | "threat_intel_match" -> EventCategory.ThreatIntelMatch
        | "cloud_audit" -> EventCategory.CloudAudit | "saas_audit" -> EventCategory.SaasAudit
        | "identity_authentication" -> EventCategory.IdentityAuthentication
        | _ -> EventCategory.NetworkConnection

    let private parseProtocol (s: string) =
        match s.ToLowerInvariant() with
        | "tcp" -> Protocol.Tcp | "udp" -> Protocol.Udp | "icmp" -> Protocol.Icmp
        | "sctp" -> Protocol.Sctp | other -> Protocol.Other other

    let private parseApp (s: string) =
        match s.ToLowerInvariant() with
        | "dns" -> AppProtocol.Dns | "http" -> AppProtocol.Http | "tls" | "ssl" -> AppProtocol.Tls
        | "smb" -> AppProtocol.Smb | "dcerpc" -> AppProtocol.Dcerpc | "rdp" -> AppProtocol.Rdp
        | "ssh" -> AppProtocol.Ssh | "ldap" -> AppProtocol.Ldap | "kerberos" -> AppProtocol.Kerberos
        | "ntlm" -> AppProtocol.Ntlm | "dhcp" -> AppProtocol.Dhcp | "" | "-" -> AppProtocol.Unknown
        | other -> AppProtocol.Other other

    let private f (fields: Map<string, string>) key = fields |> Map.tryFind key
    let private boolOf fields key = f fields key |> Option.map (fun v -> v = "true" || v = "1") |> Option.defaultValue false

    let private buildPayload (cat: EventCategory) (fields: Map<string, string>) : EventPayload =
        match cat with
        | EventCategory.Dns ->
            let q = f fields "query" |> Option.defaultValue ""
            EventPayload.Dns
                { Query = q
                  QueryType = f fields "query_type" |> Option.defaultValue "A"
                  ResponseCode = f fields "rcode" |> Option.defaultValue "NOERROR"
                  Answers = f fields "answers" |> Option.map (fun a -> a.Split(',') |> Array.toList) |> Option.defaultValue []
                  QueryLength = q.Length
                  IsNxDomain = (f fields "rcode" = Some "NXDOMAIN")
                  IsTxtQuery = (f fields "query_type" = Some "TXT") }
        | EventCategory.Http ->
            EventPayload.Http
                { Method = f fields "method" |> Option.defaultValue "GET"
                  Host = f fields "host" |> Option.defaultValue ""
                  Uri = f fields "uri" |> Option.defaultValue "/"
                  StatusCode = None; UserAgent = f fields "user_agent"; Referrer = None
                  RequestBodyLen = 0L; ResponseBodyLen = 0L; ContentType = None }
        | EventCategory.Tls ->
            EventPayload.Tls
                { Sni = f fields "sni"; TlsVersion = f fields "tls_version"; CipherSuite = f fields "cipher"
                  CertificateSubject = f fields "cert_subject"; CertificateIssuer = f fields "cert_issuer"
                  CertificateNotBefore = None; CertificateNotAfter = None
                  ClientFingerprint = f fields "ja3"; ServerFingerprint = f fields "ja3s"; Established = true }
        | EventCategory.SmbFile | EventCategory.SmbNamedPipe ->
            EventPayload.Smb
                { Share = f fields "share"; FilePath = f fields "path"; NamedPipe = f fields "named_pipe"
                  Operation = f fields "operation"; IsAdminShare = boolOf fields "is_admin_share" }
        | EventCategory.Kerberos | EventCategory.Ntlm | EventCategory.IdentityAuthentication ->
            EventPayload.Auth
                { AuthProtocol = f fields "auth_protocol" |> Option.defaultValue "unknown"
                  TargetService = f fields "target_service"
                  Result = f fields "result" |> Option.defaultValue "unknown"
                  FailureReason = f fields "failure_reason"
                  IsPrivileged = boolOf fields "is_privileged"; LogonType = f fields "logon_type" }
        | EventCategory.IdsSignatureAlert | EventCategory.IdsProtocolAlert | EventCategory.IdsDecoderEvent ->
            let intOf key dv = f fields key |> Option.bind (fun v -> match System.Int64.TryParse v with | true, n -> Some n | _ -> None) |> Option.defaultValue dv
            EventPayload.IdsAlert
                { SignatureId = intOf "signature_id" 0L
                  SignatureRevision = intOf "signature_rev" 0L |> int
                  SignatureName = f fields "signature" |> Option.defaultValue "unknown"
                  IdsCategory = f fields "ids_category" |> Option.defaultValue ""
                  IdsSeverity = intOf "ids_severity" 3L |> int
                  RuleSource = f fields "rule_source"
                  PayloadSnippet = f fields "payload" }
        | EventCategory.ThreatIntelMatch ->
            let intOf key dv = f fields key |> Option.bind (fun v -> match System.Int32.TryParse v with | true, n -> Some n | _ -> None) |> Option.defaultValue dv
            EventPayload.ThreatIntelMatch
                { Indicator = f fields "indicator" |> Option.defaultValue ""
                  IndicatorType = f fields "indicator_type" |> Option.defaultValue "ip"
                  FeedName = f fields "feed" |> Option.defaultValue "unknown"
                  ActorLabel = f fields "actor"; ToolLabel = f fields "tool"; CampaignLabel = f fields "campaign"
                  IntelConfidence = intOf "intel_confidence" 50 }
        | _ -> EventPayload.Connection

    let private parseDate (s: string) =
        match DateTimeOffset.TryParse s with | true, d -> d | _ -> DateTimeOffset.UtcNow

    let fromDto (sensorId: SensorId) (sensorName: string) (dto: IngestEventDto) : NormalizedEvent =
        let cat = parseCategory dto.Category
        let now = DateTimeOffset.UtcNow
        { EventId = EventId(Guid.NewGuid())
          Timestamp = parseDate dto.Timestamp
          ObservedTime = parseDate dto.ObservedTime
          IngestTime = now
          SourceSensorId = sensorId
          SourceSensorName = sensorName
          SourceZone = dto.Fields |> Map.tryFind "zone" |> Option.defaultValue "unknown"
          CollectorType = CollectorType.NetworkSensor
          Category = cat
          Protocol = parseProtocol dto.Protocol
          ApplicationProtocol = parseApp dto.ApplicationProtocol
          SourceIp = dto.SourceIp
          DestinationIp = dto.DestinationIp
          SourcePort = dto.SourcePort
          DestinationPort = dto.DestinationPort
          SourceMac = dto.Fields |> Map.tryFind "src_mac"
          DestinationMac = dto.Fields |> Map.tryFind "dst_mac"
          Hostname = dto.Hostname
          SourceHostname = dto.Fields |> Map.tryFind "src_hostname"
          DestinationHostname = dto.Fields |> Map.tryFind "dst_hostname"
          Username = dto.Username
          AccountName = dto.Fields |> Map.tryFind "account"
          DomainName = dto.Fields |> Map.tryFind "domain"
          DeviceId = None; AssetId = None; UserId = None
          SessionId = dto.Fields |> Map.tryFind "session_id"
          ConnectionId = dto.Fields |> Map.tryFind "connection_id"
          Direction = TrafficDirection.Unknown
          Lane = TrafficLane.Unknown
          BytesIn = dto.BytesIn; BytesOut = dto.BytesOut
          PacketsIn = dto.PacketsIn; PacketsOut = dto.PacketsOut
          DurationMs = dto.DurationMs
          Country = dto.Fields |> Map.tryFind "country"
          Asn = dto.Fields |> Map.tryFind "asn"
          Payload = buildPayload cat dto.Fields
          RiskHint = None; SeverityHint = None; ConfidenceHint = None
          RawEventReference = dto.Fields |> Map.tryFind "raw_ref"
          Enrichment = Map.empty
          Tags = [] }

    let fromDtoBatch (req: IngestBatchRequest) : Result<NormalizedEvent list, string> =
        match Guid.TryParse req.SensorId with
        | true, g ->
            let sid = SensorId g
            Ok (req.Events |> List.map (fromDto sid req.SensorName))
        | _ -> Error "invalid sensorId (must be a GUID)"

/// Async ingestion pipeline. Events arrive on a bounded channel (backpressure),
/// are classified/entity-resolved and written to the store, and on a timer the
/// detection -> scoring -> correlation cycle runs over the recent window.

type IngestionPipeline(store: AstraStore, classifier: Classifier, config: Astra.Server.Config.ServerConfig, logger: ILogger) =
    let channel =
        Channel.CreateBounded<NormalizedEvent>(
            BoundedChannelOptions(100_000,
                FullMode = BoundedChannelFullMode.DropOldest,   // shed load rather than block sensors
                SingleReader = true))
    let engine = DetectionEngine(store)
    let mutable droppedForBackpressure = 0L

    member _.Engine = engine

    /// Enrich an inbound event with classification + entity resolution, then enqueue.
    member _.Submit(evt: NormalizedEvent) =
        if classifier.IsDropped evt.SourceIp || classifier.IsDropped evt.DestinationIp then ()
        else
            let direction = classifier.Direction(evt.SourceIp, evt.DestinationIp)
            let lane = classifier.Lane(evt.SourceIp, evt.DestinationIp)
            let enriched = { evt with Direction = direction; Lane = lane }
            // resolve source/destination host entities eagerly so the queue is populated
            store.ResolveEntity(EntityType.Host, evt.SourceIp, evt.SourceIp, evt.ObservedTime) |> ignore
            if not (channel.Writer.TryWrite enriched) then
                Interlocked.Increment(&droppedForBackpressure) |> ignore

    member _.DroppedForBackpressure = Interlocked.Read(&droppedForBackpressure)

    /// Drain the channel into the store (called by the background worker).
    member _.DrainOnce(ct: CancellationToken) =
        let mutable count = 0
        let mutable go = true
        while go && not ct.IsCancellationRequested do
            match channel.Reader.TryRead() with
            | true, evt -> store.AddEvent evt; count <- count + 1
            | _ -> go <- false
        count

    /// Run detection -> scoring -> correlation over the recent window.
    member _.RunAnalysisCycle() =
        let now = DateTimeOffset.UtcNow
        let window = store.RecentEvents config.DetectionWindow
        let detections = engine.Run(window, now)
        Astra.Server.ScoringEngine.recomputeAll store now
        let incidents = Astra.Server.Correlation.correlate store now
        if not detections.IsEmpty || not incidents.IsEmpty then
            logger.LogInformation(
                "Analysis cycle: {Detections} new detections, {Incidents} new incidents over {Events} events",
                detections.Length, incidents.Length, window.Length)
        detections, incidents

/// Hosted background service that drives the pipeline on the configured interval.
type IngestionWorker(pipeline: IngestionPipeline, config: Astra.Server.Config.ServerConfig, logger: ILogger<IngestionWorker>) =
    inherit BackgroundService()
    override _.ExecuteAsync(ct: CancellationToken) =
        task {
            logger.LogInformation("Astra ingestion worker started (interval {Interval}s)", config.DetectionInterval.TotalSeconds)
            while not ct.IsCancellationRequested do
                try
                    let drained = pipeline.DrainOnce ct
                    if drained > 0 then logger.LogDebug("Drained {Count} events", drained)
                    pipeline.RunAnalysisCycle() |> ignore
                with ex ->
                    logger.LogError(ex, "Ingestion cycle failed")
                do! Tasks.Task.Delay(config.DetectionInterval, ct)
        } :> Tasks.Task
