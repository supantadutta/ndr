module Astra.Server.SeedData

open System
open Astra.Shared
open Astra.Server.Store

/// Demo seed generator. Produces sensors, health, and normalized telemetry that
/// reproduces several attack scenarios so the detection/scoring/correlation
/// engines light up the first dashboard on a cold start. All data is synthetic.

let private rng = Random(1337)

let private mkSensor id name zone mode : Sensor =
    { SensorId = SensorId id
      Name = name
      Description = sprintf "Astra network sensor - %s" zone
      Zone = zone
      Location = zone
      GroupName = "default"
      Mode = mode
      Capabilities = { ZeekEnabled = true; SuricataEnabled = true; FlowEnabled = true; PcapReplayEnabled = true }
      Version = "1.0.0"
      Status = SensorStatus.Online
      EnrolledAt = DateTimeOffset.UtcNow.AddDays(-30.0)
      LastHeartbeat = Some (DateTimeOffset.UtcNow.AddSeconds(-8.0))
      CaptureInterfaces = [ "eth1" ]
      Tags = [ zone ] }

let private baseEvent (sensor: Sensor) (now: DateTimeOffset) category proto app src dst : NormalizedEvent =
    { EventId = EventId(Guid.NewGuid())
      Timestamp = now
      ObservedTime = now
      IngestTime = now
      SourceSensorId = sensor.SensorId
      SourceSensorName = sensor.Name
      SourceZone = sensor.Zone
      CollectorType = CollectorType.NetworkSensor
      Category = category
      Protocol = proto
      ApplicationProtocol = app
      SourceIp = src
      DestinationIp = dst
      SourcePort = Some (1024 + rng.Next 60000)
      DestinationPort = None
      SourceMac = None
      DestinationMac = None
      Hostname = None
      SourceHostname = None
      DestinationHostname = None
      Username = None
      AccountName = None
      DomainName = None
      DeviceId = None
      AssetId = None
      UserId = None
      SessionId = None
      ConnectionId = Some (Guid.NewGuid().ToString("N").Substring(0, 12))
      Direction = TrafficDirection.Unknown   // set by ingestion classifier normally; set explicitly below
      Lane = TrafficLane.Unknown
      BytesIn = 0L
      BytesOut = 0L
      PacketsIn = 0L
      PacketsOut = 0L
      DurationMs = None
      Country = None
      Asn = None
      Payload = EventPayload.Connection
      RiskHint = None
      SeverityHint = None
      ConfidenceHint = None
      RawEventReference = Some (sprintf "zeek://%s/conn/%s" sensor.Name (Guid.NewGuid().ToString("N").Substring(0, 8)))
      Enrichment = Map.empty
      Tags = [] }

/// Generate all seed events. The ingestion pipeline will classify direction.
let generateEvents (sensors: Sensor list) : NormalizedEvent list =
    let hq = sensors.[0]
    let dc = if sensors.Length > 1 then sensors.[1] else sensors.[0]
    let now = DateTimeOffset.UtcNow
    let events = ResizeArray<NormalizedEvent>()

    // ---- Scenario 1: internal port scan from 10.10.5.23 ----
    let scanner = "10.10.5.23"
    for i in 0 .. 260 do
        let dst = sprintf "10.10.5.%d" (rng.Next(1, 60))
        let e = baseEvent hq (now.AddSeconds(float (-600 + i))) EventCategory.NetworkConnection Protocol.Tcp AppProtocol.Unknown scanner dst
        events.Add { e with DestinationPort = Some (rng.Next(1, 1024)); BytesOut = 60L; BytesIn = 40L; PacketsOut = 2L; PacketsIn = 1L }

    // ---- Scenario 2: DNS tunneling from 10.10.7.44 ----
    let dnsHost = "10.10.7.44"
    for i in 0 .. 80 do
        let label = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N").Substring(0, 20)
        let query = sprintf "%s.tunnel-c2-demo.net" (label.Substring(0, 52))
        let e = baseEvent hq (now.AddSeconds(float (-900 + i * 8))) EventCategory.Dns Protocol.Udp AppProtocol.Dns dnsHost "10.10.0.53"
        events.Add
            { e with
                DestinationPort = Some 53
                BytesOut = int64 query.Length
                Payload = EventPayload.Dns
                    { Query = query; QueryType = (if i % 2 = 0 then "TXT" else "A")
                      ResponseCode = "NOERROR"; Answers = []
                      QueryLength = query.Length; IsNxDomain = false; IsTxtQuery = (i % 2 = 0) } }

    // ---- Scenario 3: HTTPS beaconing from 10.10.9.15 to 203.0.113.66 every 30s ----
    let beaconHost = "10.10.9.15"
    let c2 = "203.0.113.66"
    for i in 0 .. 40 do
        let jitter = rng.NextDouble() * 2.0 - 1.0
        let ts = now.AddSeconds(-1200.0 + float i * 30.0 + jitter)
        let e = baseEvent hq ts EventCategory.Tls Protocol.Tcp AppProtocol.Tls beaconHost c2
        events.Add
            { e with
                DestinationPort = Some 443
                BytesOut = 1200L + int64 (rng.Next 300)
                BytesIn = 800L + int64 (rng.Next 200)
                PacketsOut = 6L; PacketsIn = 5L
                Payload = EventPayload.Tls
                    { Sni = Some "cdn-metrics.example-c2.net"; TlsVersion = Some "TLSv1.2"
                      CipherSuite = Some "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                      CertificateSubject = Some "CN=cdn-metrics.example-c2.net"
                      CertificateIssuer = Some "CN=Lets Encrypt"; CertificateNotBefore = None
                      CertificateNotAfter = None; ClientFingerprint = Some "ja3:6f1c2d..."
                      ServerFingerprint = None; Established = true } }

    // ---- Scenario 4: brute force + success against svc-backup from 10.10.9.15 ----
    let acct = "svc-backup"
    for i in 0 .. 14 do
        let ts = now.AddSeconds(-800.0 + float i * 20.0)
        let e = baseEvent dc ts EventCategory.Kerberos Protocol.Tcp AppProtocol.Kerberos beaconHost "10.20.0.10"
        events.Add
            { e with
                DestinationPort = Some 88
                AccountName = Some acct
                Payload = EventPayload.Auth
                    { AuthProtocol = "kerberos"; TargetService = Some "cifs/dc01"
                      Result = "failure"; FailureReason = Some "PREAUTH_FAILED"
                      IsPrivileged = true; LogonType = Some "network" } }
    // the success
    let successTs = now.AddSeconds(-490.0)
    let se = baseEvent dc successTs EventCategory.Kerberos Protocol.Tcp AppProtocol.Kerberos beaconHost "10.20.0.10"
    events.Add
        { se with
            DestinationPort = Some 88
            AccountName = Some acct
            Payload = EventPayload.Auth
                { AuthProtocol = "kerberos"; TargetService = Some "cifs/dc01"
                  Result = "success"; FailureReason = None; IsPrivileged = true; LogonType = Some "network" } }

    // ---- Scenario 5: admin-share lateral movement from 10.10.9.15 to 5 hosts ----
    for i in 0 .. 5 do
        let target = sprintf "10.20.0.%d" (20 + i)
        let ts = now.AddSeconds(-450.0 + float i * 15.0)
        let e = baseEvent dc ts EventCategory.SmbFile Protocol.Tcp AppProtocol.Smb beaconHost target
        events.Add
            { e with
                DestinationPort = Some 445
                BytesOut = 250000L
                Payload = EventPayload.Smb
                    { Share = Some "ADMIN$"; FilePath = Some "\\Windows\\Temp\\svc.exe"
                      NamedPipe = Some "svcctl"; Operation = Some "write"; IsAdminShare = true } }

    // ---- Scenario 6: large exfil upload from 10.10.9.15 to rare 198.51.100.9 ----
    for i in 0 .. 20 do
        let ts = now.AddSeconds(-300.0 + float i * 8.0)
        let e = baseEvent hq ts EventCategory.NetworkConnection Protocol.Tcp AppProtocol.Tls beaconHost "198.51.100.9"
        events.Add
            { e with
                DestinationPort = Some 443
                BytesOut = 6_000_000L
                BytesIn = 40_000L
                PacketsOut = 4200L; PacketsIn = 300L }

    // ---- background benign noise: broad, popular external destinations ----
    let benignHosts = [ for i in 1..25 -> sprintf "10.10.%d.%d" (rng.Next(1, 30)) (rng.Next(2, 250)) ]
    let popularDsts = [ "93.184.216.34"; "142.250.72.14"; "151.101.1.140" ]
    for h in benignHosts do
        for d in popularDsts do
            let ts = now.AddSeconds(float (-rng.Next 3600))
            let e = baseEvent hq ts EventCategory.Tls Protocol.Tcp AppProtocol.Tls h d
            events.Add { e with DestinationPort = Some 443; BytesOut = int64 (rng.Next 5000); BytesIn = int64 (rng.Next 50000) }

    events |> List.ofSeq

let seedSensors () : Sensor list =
    [ mkSensor (Guid("11111111-1111-1111-1111-111111111111")) "sensor-hq-core" "hq-campus" SensorMode.LiveCapture
      mkSensor (Guid("22222222-2222-2222-2222-222222222222")) "sensor-datacenter" "datacenter" SensorMode.LiveCapture
      mkSensor (Guid("33333333-3333-3333-3333-333333333333")) "sensor-dmz-edge" "dmz" SensorMode.LiveCapture ]

let seedHealth (sensors: Sensor list) : SensorHealthSample list =
    sensors
    |> List.mapi (fun i s ->
        { SensorId = s.SensorId
          SampledAt = DateTimeOffset.UtcNow.AddSeconds(-8.0)
          CpuPercent = 22.0 + float (i * 7)
          MemoryPercent = 41.0 + float (i * 5)
          DiskPercent = 55.0 + float (i * 3)
          InterfaceUp = true
          PacketDropPercent = if i = 2 then 1.8 else 0.1
          EventsPerSecond = 1450.0 - float (i * 200)
          BufferedEvents = 0L
          ZeekRunning = true
          SuricataRunning = true
          Errors = if i = 2 then [ "capture buffer pressure on eth1" ] else [] })
