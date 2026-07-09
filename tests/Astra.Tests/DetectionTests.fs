module Astra.Tests.DetectionTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Server.DetectionEngine
open Astra.Tests.Fixtures

let private run (events: NormalizedEvent list) =
    let store = AstraStore()
    let engine = DetectionEngine(store)
    engine.Run(events, DateTimeOffset.UtcNow), store

[<Fact>]
let ``port scan rule fires on high port fanout`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    let detections, _ = run events
    Assert.Contains(detections, fun d -> d.RuleId = RuleId "recon.internal_port_scan")

[<Fact>]
let ``port scan rule stays silent on normal traffic`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 5 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" "10.0.0.9" (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some 443) ]
    let detections, _ = run events
    Assert.DoesNotContain(detections, fun d -> d.RuleId = RuleId "recon.internal_port_scan")

[<Fact>]
let ``beaconing rule fires on regular external intervals`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 0 .. 20 ->
            mkEvent EventCategory.Tls AppProtocol.Tls "10.0.0.5" "203.0.113.9" (now.AddSeconds(float (i * 30)))
            |> withDirection TrafficDirection.InternalToExternal ]
    let detections, _ = run events
    Assert.Contains(detections, fun d -> d.RuleId = RuleId "c2.beaconing")

[<Fact>]
let ``brute force then success fires and is Critical`` () =
    let now = DateTimeOffset.UtcNow
    let auth result at =
        let e = mkEvent EventCategory.Kerberos AppProtocol.Kerberos "10.0.0.5" "10.0.0.10" at
        { e with
            AccountName = Some "svc-test"
            Payload = EventPayload.Auth
                { AuthProtocol = "kerberos"; TargetService = Some "cifs/dc"; Result = result
                  FailureReason = None; IsPrivileged = true; LogonType = Some "network" } }
    let events =
        [ for i in 0 .. 11 -> auth "failure" (now.AddSeconds(float (i * 10))) ]
        @ [ auth "success" (now.AddSeconds 200.0) ]
    let detections, _ = run events
    let d = detections |> List.find (fun d -> d.RuleId = RuleId "cred.bruteforce_then_success")
    Assert.Equal(Severity.Critical, d.Severity)

[<Fact>]
let ``ids signature rule fires on high severity alert`` () =
    let now = DateTimeOffset.UtcNow
    let alert =
        let e =
            mkEvent EventCategory.IdsSignatureAlert AppProtocol.Unknown "10.0.0.5" "10.0.0.9" now
            |> withDirection TrafficDirection.ExternalToInternal
        { e with
            Payload = EventPayload.IdsAlert
                { SignatureId = 2028371L; SignatureRevision = 3; SignatureName = "ET MALWARE Test"
                  IdsCategory = "trojan"; IdsSeverity = 1; RuleSource = Some "suricata"; PayloadSnippet = None } }
    let detections, _ = run [ alert ]
    Assert.Contains(detections, fun d -> d.RuleId = RuleId "signature.high_severity_ids_alert")

[<Fact>]
let ``a rule does not raise duplicate detections for the same entity`` () =
    let now = DateTimeOffset.UtcNow
    let events =
        [ for i in 1 .. 150 ->
            mkEvent EventCategory.NetworkConnection AppProtocol.Unknown "10.0.0.5" (sprintf "10.0.0.%d" (i % 60 + 1)) (now.AddSeconds(float -i))
            |> withPorts (Some 40000) (Some i) ]
    let store = AstraStore()
    let engine = DetectionEngine(store)
    engine.Run(events, now) |> ignore
    let second = engine.Run(events, now)   // same window again
    Assert.DoesNotContain(second, fun d -> d.RuleId = RuleId "recon.internal_port_scan")
