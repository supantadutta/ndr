module Astra.Tests.Fixtures

open System
open Astra.Shared

/// Builders for constructing NormalizedEvents in tests without a live pipeline.

let sensorId = SensorId(Guid("11111111-1111-1111-1111-111111111111"))

let mkEvent category app src dst (at: DateTimeOffset) : NormalizedEvent =
    { EventId = EventId(Guid.NewGuid())
      Timestamp = at
      ObservedTime = at
      IngestTime = at
      SourceSensorId = sensorId
      SourceSensorName = "test-sensor"
      SourceZone = "test"
      CollectorType = CollectorType.NetworkSensor
      Category = category
      Protocol = Protocol.Tcp
      ApplicationProtocol = app
      SourceIp = src
      DestinationIp = dst
      SourcePort = Some 40000
      DestinationPort = Some 443
      SourceMac = None; DestinationMac = None
      Hostname = None; SourceHostname = None; DestinationHostname = None
      Username = None; AccountName = None; DomainName = None
      DeviceId = None; AssetId = None; UserId = None
      SessionId = None; ConnectionId = None
      Direction = TrafficDirection.InternalToInternal
      Lane = TrafficLane.EastWest
      BytesIn = 0L; BytesOut = 0L; PacketsIn = 0L; PacketsOut = 0L
      DurationMs = None; Country = None; Asn = None
      Payload = EventPayload.Connection
      RiskHint = None; SeverityHint = None; ConfidenceHint = None
      RawEventReference = None; Enrichment = Map.empty; Tags = [] }

let withPorts sp dp (e: NormalizedEvent) = { e with SourcePort = sp; DestinationPort = dp }
let withDirection d (e: NormalizedEvent) = { e with Direction = d }
let withBytes bIn bOut (e: NormalizedEvent) = { e with BytesIn = bIn; BytesOut = bOut }
