module Astra.Server.DetectionEngine

open System
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Astra NDR detection engine (Phase 1 skeleton with real starter rules).
///
/// A rule consumes a sliding window of normalized events plus the entity
/// store, and emits fully-explained Detection records. Rules are pure given
/// their input, unit-testable, and individually tunable via thresholds.
/// ============================================================================

type RuleInput =
    { Window: NormalizedEvent list
      Now: DateTimeOffset
      Store: AstraStore }

type IDetectionRule =
    abstract Definition: DetectionRuleDef
    abstract Evaluate: RuleInput -> Detection list

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

let mkRuleDef ruleId name description engineKind category tactic techId techName killChain severity confidence thresholds =
    { RuleId = RuleId ruleId
      Name = name
      Description = description
      EngineKind = engineKind
      Category = category
      Tactic = tactic
      TechniqueId = techId
      TechniqueName = techName
      KillChainStage = killChain
      DefaultSeverity = severity
      DefaultConfidence = confidence
      Enabled = true
      Thresholds = Map.ofList thresholds
      Version = 1
      Author = "astra-core"
      CreatedAt = DateTimeOffset.UtcNow
      UpdatedAt = DateTimeOffset.UtcNow }

type DetectionDraft =
    { Title: string
      Summary: string
      AffectedEntity: EntityProfile
      SourceEntity: EntityProfile option
      TargetEntity: EntityProfile option
      Evidence: EvidenceItem list
      Events: NormalizedEvent list
      BaselineComparisons: BaselineComparison list
      WhySuspicious: string
      FalsePositives: string list
      InvestigationSteps: string list
      ResponseActions: string list
      TuningFields: (string * string) list
      ConfidenceOverride: int option
      SeverityOverride: Severity option }

let materialize (def: DetectionRuleDef) (now: DateTimeOffset) (draft: DetectionDraft) : Detection =
    let events = draft.Events
    let severity = defaultArg draft.SeverityOverride def.DefaultSeverity
    let confidence = defaultArg draft.ConfidenceOverride def.DefaultConfidence
    let threat = min 100 ((Severity.toInt severity + confidence) / 2 + 10)
    { DetectionId = DetectionId(Guid.NewGuid())
      EngineKind = def.EngineKind
      RuleId = def.RuleId
      Title = draft.Title
      Summary = draft.Summary
      Description = def.Description
      Category = def.Category
      Tactic = def.Tactic
      TechniqueId = def.TechniqueId
      TechniqueName = def.TechniqueName
      KillChainStage = def.KillChainStage
      Severity = severity
      Confidence = confidence
      Certainty = confidence
      ThreatScore = threat
      UrgencyContribution = threat
      AffectedEntity = draft.AffectedEntity.EntityId
      SourceEntity = draft.SourceEntity |> Option.map (fun e -> e.EntityId)
      TargetEntity = draft.TargetEntity |> Option.map (fun e -> e.EntityId)
      RelatedEntities =
        [ yield! draft.SourceEntity |> Option.toList
          yield! draft.TargetEntity |> Option.toList ]
        |> List.map (fun e -> e.EntityId)
      Evidence = draft.Evidence
      EvidenceReferences = events |> List.truncate 20 |> List.choose (fun e -> e.RawEventReference)
      EventIds = events |> List.truncate 200 |> List.map (fun e -> e.EventId)
      TimelineStart = if events.IsEmpty then now else events |> List.map (fun e -> e.Timestamp) |> List.min
      TimelineEnd = if events.IsEmpty then now else events |> List.map (fun e -> e.Timestamp) |> List.max
      BaselineComparisons = draft.BaselineComparisons
      WhySuspicious = draft.WhySuspicious
      FalsePositiveConsiderations = draft.FalsePositives
      RecommendedInvestigationSteps = draft.InvestigationSteps
      RecommendedResponseActions = draft.ResponseActions
      TuningFields = Map.ofList draft.TuningFields
      TriageState = TriageState.Untriaged
      AssignedOwner = None
      Status = "open"
      CreatedAt = now
      UpdatedAt = now }

let private evidence label value (events: NormalizedEvent list) =
    { Label = label; Value = value; EventIds = events |> List.truncate 50 |> List.map (fun e -> e.EventId) }

let private threshold (def: DetectionRuleDef) key fallback =
    def.Thresholds |> Map.tryFind key |> Option.defaultValue fallback

// ---------------------------------------------------------------------------
// Rule: internal port scan (vertical + horizontal)  [Reconnaissance]
// ---------------------------------------------------------------------------

type InternalPortScanRule() =
    let def =
        mkRuleDef "recon.internal_port_scan"
            "Internal Port Scan"
            "An internal host contacted an unusually high number of distinct ports or hosts in a short window, consistent with active network reconnaissance."
            DetectionEngineKind.Behavioral DetectionCategory.Reconnaissance
            MitreTactic.Discovery "T1046" "Network Service Discovery"
            KillChainStage.Reconnaissance Severity.Medium 75
            [ "distinct_ports", 100.0; "distinct_hosts", 50.0 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let portThreshold = threshold def "distinct_ports" 100.0 |> int
            let hostThreshold = threshold def "distinct_hosts" 50.0 |> int
            input.Window
            |> List.filter (fun e ->
                e.Direction = TrafficDirection.InternalToInternal
                && e.Category = EventCategory.NetworkConnection)
            |> List.groupBy (fun e -> e.SourceIp)
            |> List.choose (fun (srcIp, evts) ->
                let distinctPorts = evts |> List.choose (fun e -> e.DestinationPort) |> List.distinct |> List.length
                let distinctHosts = evts |> List.map (fun e -> e.DestinationIp) |> List.distinct |> List.length
                let vertical = distinctPorts >= portThreshold
                let horizontal = distinctHosts >= hostThreshold
                if not (vertical || horizontal) then None
                else
                    let src = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                    if input.Store.HasOpenDetection((RuleId "recon.internal_port_scan"), src.EntityId) then None
                    else
                    let scanKind = if vertical && horizontal then "vertical + horizontal" elif vertical then "vertical" else "horizontal"
                    Some (materialize def input.Now
                        { Title = sprintf "Internal port scan from %s" src.DisplayName
                          Summary = sprintf "%s scanned %d distinct ports across %d hosts (%s scan pattern)." src.DisplayName distinctPorts distinctHosts scanKind
                          AffectedEntity = src
                          SourceEntity = Some src
                          TargetEntity = None
                          Evidence =
                            [ evidence "distinct destination ports" (string distinctPorts) evts
                              evidence "distinct destination hosts" (string distinctHosts) evts
                              evidence "scan pattern" scanKind [] ]
                          Events = evts
                          BaselineComparisons =
                            [ { Metric = "distinct_internal_peers_per_window"
                                BaselineValue = "typically < 10"
                                ObservedValue = string distinctHosts
                                DeviationDescription = "well above normal east-west fanout for this host" } ]
                          WhySuspicious = "Legitimate hosts rarely enumerate large port or host ranges; this pattern matches active service discovery that typically precedes lateral movement."
                          FalsePositives =
                            [ "Authorized vulnerability scanners and asset-inventory tools"
                              "Monitoring systems performing service checks" ]
                          InvestigationSteps =
                            [ "Confirm whether the source host runs an authorized scanning tool"
                              "Review what services responded and whether follow-on connections occurred"
                              "Check the host for recent detections in other categories (C2, credential attack)" ]
                          ResponseActions =
                            [ "Add host to watch list"; "Isolate host (simulation) if unauthorized" ]
                          TuningFields = [ "source_ip", srcIp; "detection_type", "recon.internal_port_scan" ]
                          ConfidenceOverride = None
                          SeverityOverride = if vertical && horizontal then Some Severity.High else None }))

// ---------------------------------------------------------------------------
// Rule: DNS tunneling indicators  [Command and Control]
// ---------------------------------------------------------------------------

type DnsTunnelIndicatorsRule() =
    let def =
        mkRuleDef "c2.dns_tunnel_indicators"
            "Hidden DNS Tunnel Indicators"
            "A host issued a sustained stream of unusually long or TXT-heavy DNS queries to a single domain, consistent with DNS tunneling for command-and-control or exfiltration."
            DetectionEngineKind.Behavioral DetectionCategory.CommandAndControl
            MitreTactic.CommandAndControl "T1071.004" "Application Layer Protocol: DNS"
            KillChainStage.CommandAndControl Severity.High 70
            [ "min_queries", 30.0; "avg_query_length", 50.0; "txt_ratio", 0.5 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let minQueries = threshold def "min_queries" 30.0 |> int
            let lenThreshold = threshold def "avg_query_length" 50.0
            let txtRatioThreshold = threshold def "txt_ratio" 0.5

            let domainOf (q: string) =
                let parts = q.TrimEnd('.').Split('.')
                if parts.Length >= 2 then sprintf "%s.%s" parts.[parts.Length - 2] parts.[parts.Length - 1]
                else q

            input.Window
            |> List.choose (fun e ->
                match e.Payload with
                | EventPayload.Dns d -> Some (e, d)
                | _ -> None)
            |> List.groupBy (fun (e, d) -> e.SourceIp, domainOf d.Query)
            |> List.choose (fun ((srcIp, domain), pairs) ->
                let count = pairs.Length
                if count < minQueries then None
                else
                    let avgLen = pairs |> List.averageBy (fun (_, d) -> float d.QueryLength)
                    let txtRatio = float (pairs |> List.filter (fun (_, d) -> d.IsTxtQuery) |> List.length) / float count
                    if avgLen < lenThreshold && txtRatio < txtRatioThreshold then None
                    else
                        let src = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                        if input.Store.HasOpenDetection((RuleId "c2.dns_tunnel_indicators"), src.EntityId) then None
                        else
                        let evts = pairs |> List.map fst
                        let domainEntity = input.Store.ResolveEntity(EntityType.Domain, domain, domain, input.Now)
                        Some (materialize def input.Now
                            { Title = sprintf "DNS tunneling indicators: %s -> %s" src.DisplayName domain
                              Summary = sprintf "%d DNS queries to %s with average query length %.0f chars and %.0f%% TXT records." count domain avgLen (txtRatio * 100.0)
                              AffectedEntity = src
                              SourceEntity = Some src
                              TargetEntity = Some domainEntity
                              Evidence =
                                [ evidence "queries in window" (string count) evts
                                  evidence "average query length" (sprintf "%.0f characters" avgLen) evts
                                  evidence "TXT query ratio" (sprintf "%.0f%%" (txtRatio * 100.0)) evts
                                  evidence "target domain" domain [] ]
                              Events = evts
                              BaselineComparisons =
                                [ { Metric = "avg_dns_query_length"
                                    BaselineValue = "18-25 characters (environment norm)"
                                    ObservedValue = sprintf "%.0f characters" avgLen
                                    DeviationDescription = "query names are far longer than normal lookups, consistent with encoded payloads" } ]
                              WhySuspicious = "Long encoded subdomains and heavy TXT usage against a single domain are the classic transport pattern for DNS tunnels, which attackers use to bypass egress controls."
                              FalsePositives =
                                [ "Some security products and CDNs encode data in DNS labels"
                                  "Anti-spam/telemetry services with long TXT lookups" ]
                              InvestigationSteps =
                                [ "Inspect the raw query names for base32/base64-like encoding"
                                  "Check registration age and reputation of the domain"
                                  "Look for corresponding process activity on the endpoint if EDR is available" ]
                              ResponseActions =
                                [ "Block domain at DNS resolver (requires approval)"
                                  "Add domain to threat intel watch list" ]
                              TuningFields = [ "source_ip", srcIp; "domain", domain; "detection_type", "c2.dns_tunnel_indicators" ]
                              ConfidenceOverride = None
                              SeverityOverride = None }))

// ---------------------------------------------------------------------------
// Rule: HTTP/HTTPS beaconing  [Command and Control]
// ---------------------------------------------------------------------------

type BeaconingRule() =
    let def =
        mkRuleDef "c2.beaconing"
            "Periodic Beaconing to External Destination"
            "A host repeatedly connected to the same external destination at highly regular intervals, consistent with malware beaconing to command-and-control infrastructure."
            DetectionEngineKind.Statistical DetectionCategory.CommandAndControl
            MitreTactic.CommandAndControl "T1071.001" "Application Layer Protocol: Web Protocols"
            KillChainStage.CommandAndControl Severity.High 72
            [ "min_connections", 8.0; "max_interval_cv", 0.25 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let minConnections = threshold def "min_connections" 8.0 |> int
            let maxCv = threshold def "max_interval_cv" 0.25

            input.Window
            |> List.filter (fun e ->
                e.Direction = TrafficDirection.InternalToExternal
                && (e.ApplicationProtocol = AppProtocol.Http || e.ApplicationProtocol = AppProtocol.Tls))
            |> List.groupBy (fun e -> e.SourceIp, e.DestinationIp)
            |> List.choose (fun ((srcIp, dstIp), evts) ->
                if evts.Length < minConnections then None
                else
                    let times = evts |> List.map (fun e -> e.Timestamp) |> List.sort
                    let intervals =
                        times
                        |> List.pairwise
                        |> List.map (fun (a, b) -> (b - a).TotalSeconds)
                        |> List.filter (fun s -> s > 0.5)
                    if intervals.Length < minConnections - 2 then None
                    else
                        let mean = List.average intervals
                        let std = sqrt (intervals |> List.averageBy (fun x -> (x - mean) * (x - mean)))
                        let cv = if mean > 0.0 then std / mean else 999.0
                        if cv > maxCv || mean < 5.0 then None
                        else
                            let src = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                            if input.Store.HasOpenDetection((RuleId "c2.beaconing"), src.EntityId) then None
                            else
                            let dst = input.Store.ResolveEntity(EntityType.ExternalDestination, dstIp, dstIp, input.Now)
                            let sni =
                                evts
                                |> List.tryPick (fun e ->
                                    match e.Payload with
                                    | EventPayload.Tls t -> t.Sni
                                    | EventPayload.Http h -> Some h.Host
                                    | _ -> None)
                            Some (materialize def input.Now
                                { Title = sprintf "Beaconing: %s -> %s every ~%.0fs" src.DisplayName (defaultArg sni dstIp) mean
                                  Summary = sprintf "%d connections at a stable ~%.0f second interval (coefficient of variation %.2f) to external destination %s." evts.Length mean cv dstIp
                                  AffectedEntity = src
                                  SourceEntity = Some src
                                  TargetEntity = Some dst
                                  Evidence =
                                    [ evidence "connections in window" (string evts.Length) evts
                                      evidence "mean interval" (sprintf "%.1f seconds" mean) evts
                                      evidence "interval regularity (CV)" (sprintf "%.3f (lower = more machine-like)" cv) evts
                                      evidence "destination" (defaultArg sni dstIp) [] ]
                                  Events = evts
                                  BaselineComparisons =
                                    [ { Metric = "connection_interval_regularity"
                                        BaselineValue = "human/browser traffic CV typically > 0.6"
                                        ObservedValue = sprintf "CV %.2f" cv
                                        DeviationDescription = "machine-regular timing inconsistent with interactive browsing" } ]
                                  WhySuspicious = "Malware implants poll their C2 on fixed timers. Highly regular intervals to a single external destination, sustained over time, rarely occur in legitimate user traffic."
                                  FalsePositives =
                                    [ "Software update checks and telemetry agents"
                                      "Monitoring probes and health checks"
                                      "NTP-adjacent or keep-alive traffic from appliances" ]
                                  InvestigationSteps =
                                    [ "Identify the destination's reputation, registration age and hosting ASN"
                                      "Check whether other internal hosts contact the same destination"
                                      "Pivot to DNS: was the destination resolved, or contacted by raw IP?" ]
                                  ResponseActions =
                                    [ "Add destination to blocklist feed (requires approval)"
                                      "Isolate host (simulation) if corroborated" ]
                                  TuningFields =
                                    [ "source_ip", srcIp; "destination_ip", dstIp
                                      "detection_type", "c2.beaconing" ]
                                  ConfidenceOverride = None
                                  SeverityOverride = None }))

// ---------------------------------------------------------------------------
// Rule: brute force followed by success  [Credential Attack]
// ---------------------------------------------------------------------------

type BruteForceAuthRule() =
    let def =
        mkRuleDef "cred.bruteforce_then_success"
            "Successful Authentication After Repeated Failures"
            "An account experienced a burst of failed authentications followed by a success from the same source, consistent with brute force or password spraying that succeeded."
            DetectionEngineKind.Behavioral DetectionCategory.CredentialAttack
            MitreTactic.CredentialAccess "T1110" "Brute Force"
            KillChainStage.Exploitation Severity.Critical 80
            [ "min_failures", 10.0 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let minFailures = threshold def "min_failures" 10.0 |> int
            input.Window
            |> List.choose (fun e ->
                match e.Payload with
                | EventPayload.Auth a -> Some (e, a)
                | _ -> None)
            |> List.groupBy (fun (e, _) -> e.SourceIp, (defaultArg e.AccountName "unknown"))
            |> List.choose (fun ((srcIp, account), pairs) ->
                let ordered = pairs |> List.sortBy (fun (e, _) -> e.Timestamp)
                let failures = ordered |> List.filter (fun (_, a) -> a.Result = "failure")
                let successAfter =
                    match failures |> List.tryLast with
                    | Some (lastFail, _) ->
                        ordered |> List.tryFind (fun (e, a) -> a.Result = "success" && e.Timestamp > lastFail.Timestamp)
                    | None -> None
                match successAfter with
                | Some (successEvt, successAuth) when failures.Length >= minFailures ->
                    let acct = input.Store.ResolveEntity(EntityType.Account, account, account, input.Now)
                    if input.Store.HasOpenDetection((RuleId "cred.bruteforce_then_success"), acct.EntityId) then None
                    else
                    let srcHost = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                    let evts = (ordered |> List.map fst)
                    Some (materialize def input.Now
                        { Title = sprintf "Brute force success: account %s from %s" account srcIp
                          Summary = sprintf "%d failed authentications followed by a successful %s logon for %s from %s." failures.Length successAuth.AuthProtocol account srcIp
                          AffectedEntity = acct
                          SourceEntity = Some srcHost
                          TargetEntity = None
                          Evidence =
                            [ evidence "failed attempts before success" (string failures.Length) (failures |> List.map fst)
                              evidence "successful logon" (sprintf "%s at %s" successAuth.AuthProtocol (successEvt.Timestamp.ToString("u"))) [ successEvt ]
                              evidence "source" srcIp [] ]
                          Events = evts
                          BaselineComparisons =
                            [ { Metric = "auth_failures_per_window"
                                BaselineValue = "0-3 typical for this account"
                                ObservedValue = string failures.Length
                                DeviationDescription = "failure burst far above account norm, then success" } ]
                          WhySuspicious = "A long run of failures ending in a success is the signature of credential guessing that worked. The account should be considered potentially compromised until verified."
                          FalsePositives =
                            [ "User mistyping a recently changed password"
                              "Misconfigured service retrying with stale credentials, then fixed" ]
                          InvestigationSteps =
                            [ "Verify with the account owner whether the successful logon was expected"
                              "Review what the account accessed immediately after the success"
                              "Check the source host for other detections (scanning, C2)" ]
                          ResponseActions =
                            [ "Disable account (simulation, requires approval)"
                              "Force credential reset"; "Isolate source host (simulation)" ]
                          TuningFields = [ "account", account; "source_ip", srcIp; "detection_type", "cred.bruteforce_then_success" ]
                          ConfidenceOverride = None
                          SeverityOverride = None })
                | _ -> None)

// ---------------------------------------------------------------------------
// Rule: workstation-to-workstation admin share  [Lateral Movement]
// ---------------------------------------------------------------------------

type AdminShareLateralRule() =
    let def =
        mkRuleDef "lateral.admin_share_access"
            "Administrative Share Access Between Workstations"
            "A workstation accessed administrative shares (C$/ADMIN$) on other internal hosts — a pattern used by remote-execution tooling to stage payloads and move laterally."
            DetectionEngineKind.Rule DetectionCategory.LateralMovement
            MitreTactic.LateralMovement "T1021.002" "Remote Services: SMB/Windows Admin Shares"
            KillChainStage.LateralMovement Severity.High 78
            [ "min_targets", 1.0 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let minTargets = threshold def "min_targets" 1.0 |> int
            input.Window
            |> List.choose (fun e ->
                match e.Payload with
                | EventPayload.Smb s when s.IsAdminShare && e.Direction = TrafficDirection.InternalToInternal -> Some (e, s)
                | _ -> None)
            |> List.groupBy (fun (e, _) -> e.SourceIp)
            |> List.choose (fun (srcIp, pairs) ->
                let targets = pairs |> List.map (fun (e, _) -> e.DestinationIp) |> List.distinct
                if targets.Length < minTargets then None
                else
                    let src = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                    if input.Store.HasOpenDetection((RuleId "lateral.admin_share_access"), src.EntityId) then None
                    else
                    let evts = pairs |> List.map fst
                    let shares = pairs |> List.choose (fun (_, s) -> s.Share) |> List.distinct
                    Some (materialize def input.Now
                        { Title = sprintf "Admin share access from %s to %d host(s)" src.DisplayName targets.Length
                          Summary = sprintf "%s accessed administrative shares (%s) on %d internal hosts." src.DisplayName (String.concat ", " shares) targets.Length
                          AffectedEntity = src
                          SourceEntity = Some src
                          TargetEntity = None
                          Evidence =
                            [ evidence "target hosts" (String.concat ", " (targets |> List.truncate 10)) evts
                              evidence "shares accessed" (String.concat ", " shares) evts
                              evidence "smb operations" (string evts.Length) evts ]
                          Events = evts
                          BaselineComparisons =
                            [ { Metric = "admin_share_usage"
                                BaselineValue = "not previously observed from this host"
                                ObservedValue = sprintf "%d hosts in window" targets.Length
                                DeviationDescription = "new administrative SMB behavior for this source" } ]
                          WhySuspicious = "PsExec-style tooling, ransomware deployment and manual lateral movement all rely on writing to C$/ADMIN$ shares. Ordinary workstations almost never do this."
                          FalsePositives =
                            [ "IT administration from a designated admin workstation"
                              "Software deployment systems (verify the source is authorized)" ]
                          InvestigationSteps =
                            [ "Determine what files were written and whether services/scheduled tasks were created"
                              "Check the account used for the SMB sessions and its recent authentication history"
                              "Look for prior C2 or credential-attack detections on the source host" ]
                          ResponseActions =
                            [ "Isolate source host (simulation, requires approval)"
                              "Block SMB from source at internal firewall (simulation)" ]
                          TuningFields = [ "source_ip", srcIp; "detection_type", "lateral.admin_share_access" ]
                          ConfidenceOverride = None
                          SeverityOverride = if targets.Length >= 5 then Some Severity.Critical else None }))

// ---------------------------------------------------------------------------
// Rule: large upload to rare external destination  [Exfiltration]
// ---------------------------------------------------------------------------

type RareDestinationExfilRule() =
    let def =
        mkRuleDef "exfil.large_upload_rare_destination"
            "Large Upload to Rare External Destination"
            "A host uploaded a large volume of data to an external destination that is rarely or never contacted by the rest of the environment, with an outbound-dominated byte ratio."
            DetectionEngineKind.Statistical DetectionCategory.Exfiltration
            MitreTactic.Exfiltration "T1048" "Exfiltration Over Alternative Protocol"
            KillChainStage.ActionOnObjectives Severity.High 68
            [ "min_bytes_out", 50_000_000.0; "max_peer_count", 2.0; "min_out_in_ratio", 5.0 ]

    interface IDetectionRule with
        member _.Definition = def
        member _.Evaluate input =
            let minBytesOut = threshold def "min_bytes_out" 50_000_000.0 |> int64
            let maxPeers = threshold def "max_peer_count" 2.0 |> int
            let minRatio = threshold def "min_out_in_ratio" 5.0

            let external = input.Window |> List.filter (fun e -> e.Direction = TrafficDirection.InternalToExternal)
            // environment-wide popularity of each external destination
            let popularity =
                external
                |> List.groupBy (fun e -> e.DestinationIp)
                |> List.map (fun (dst, evts) -> dst, evts |> List.map (fun e -> e.SourceIp) |> List.distinct |> List.length)
                |> Map.ofList

            external
            |> List.groupBy (fun e -> e.SourceIp, e.DestinationIp)
            |> List.choose (fun ((srcIp, dstIp), evts) ->
                let bytesOut = evts |> List.sumBy (fun e -> e.BytesOut)
                let bytesIn = evts |> List.sumBy (fun e -> e.BytesIn)
                let ratio = if bytesIn > 0L then float bytesOut / float bytesIn else float bytesOut
                let peerCount = popularity |> Map.tryFind dstIp |> Option.defaultValue 0
                if bytesOut < minBytesOut || peerCount > maxPeers || ratio < minRatio then None
                else
                    let src = input.Store.ResolveEntity(EntityType.Host, srcIp, srcIp, input.Now)
                    if input.Store.HasOpenDetection((RuleId "exfil.large_upload_rare_destination"), src.EntityId) then None
                    else
                    let dst = input.Store.ResolveEntity(EntityType.ExternalDestination, dstIp, dstIp, input.Now)
                    Some (materialize def input.Now
                        { Title = sprintf "Large upload: %s sent %.1f MB to rare destination %s" src.DisplayName (float bytesOut / 1e6) dstIp
                          Summary = sprintf "%.1f MB outbound vs %.1f MB inbound (ratio %.1fx) to %s, contacted by only %d host(s) environment-wide." (float bytesOut / 1e6) (float bytesIn / 1e6) ratio dstIp peerCount
                          AffectedEntity = src
                          SourceEntity = Some src
                          TargetEntity = Some dst
                          Evidence =
                            [ evidence "bytes uploaded" (sprintf "%.1f MB" (float bytesOut / 1e6)) evts
                              evidence "upload/download ratio" (sprintf "%.1fx" ratio) evts
                              evidence "destination rarity" (sprintf "contacted by %d internal host(s)" peerCount) evts ]
                          Events = evts
                          BaselineComparisons =
                            [ { Metric = "bytes_out_per_destination"
                                BaselineValue = "typical uploads < 5 MB per destination per window"
                                ObservedValue = sprintf "%.1f MB" (float bytesOut / 1e6)
                                DeviationDescription = "order-of-magnitude above normal outbound volume" } ]
                          WhySuspicious = "Data staging and exfiltration produce upload-dominated flows to destinations the rest of the environment never touches. Rarity plus volume plus direction is a strong combined signal."
                          FalsePositives =
                            [ "Legitimate backups to a new cloud provider"
                              "Developers pushing large artifacts to a personal repository" ]
                          InvestigationSteps =
                            [ "Identify the destination owner (ASN, hosting provider, reputation)"
                              "Determine what data the source host can access"
                              "Check for preceding internal collection activity (SMB reads, database queries)" ]
                          ResponseActions =
                            [ "Block destination (requires approval)"
                              "Isolate host (simulation) pending investigation" ]
                          TuningFields = [ "source_ip", srcIp; "destination_ip", dstIp; "detection_type", "exfil.large_upload_rare_destination" ]
                          ConfidenceOverride = None
                          SeverityOverride = None }))

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

type DetectionEngine(store: AstraStore) =
    let rules: IDetectionRule list =
        [ InternalPortScanRule()
          DnsTunnelIndicatorsRule()
          BeaconingRule()
          BruteForceAuthRule()
          AdminShareLateralRule()
          RareDestinationExfilRule() ]

    member _.Rules = rules
    member _.RuleDefinitions = rules |> List.map (fun r -> r.Definition)

    /// Evaluate all enabled rules over the window; store and return new detections.
    member _.Run(window: NormalizedEvent list, now: DateTimeOffset) =
        let input = { Window = window; Now = now; Store = store }
        let produced =
            rules
            |> List.filter (fun r -> r.Definition.Enabled)
            |> List.collect (fun r ->
                try r.Evaluate input
                with _ -> [])   // a failing rule must never take down the pipeline
        for d in produced do
            store.AddDetection d
            // update affected entity's counters
            match store.TryGetEntity d.AffectedEntity with
            | Some e -> store.UpsertEntity { e with RelatedDetectionCount = e.RelatedDetectionCount + 1 }
            | None -> ()
        produced
