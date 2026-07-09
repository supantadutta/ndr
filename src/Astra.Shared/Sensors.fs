namespace Astra.Shared

open System

[<RequireQualifiedAccess>]
type SensorStatus =
    | Online
    | Degraded
    | Offline
    | Enrolling
    | Disabled

[<RequireQualifiedAccess>]
type SensorMode =
    | LiveCapture      // SPAN/TAP/mirror
    | CloudMirror
    | PcapReplay
    | LogCollection    // Zeek/Suricata log tailing only

type SensorCapabilities =
    { ZeekEnabled: bool
      SuricataEnabled: bool
      FlowEnabled: bool
      PcapReplayEnabled: bool }

type Sensor =
    { SensorId: SensorId
      Name: string
      Description: string
      Zone: string
      Location: string
      GroupName: string
      Mode: SensorMode
      Capabilities: SensorCapabilities
      Version: string
      Status: SensorStatus
      EnrolledAt: DateTimeOffset
      LastHeartbeat: DateTimeOffset option
      CaptureInterfaces: string list
      Tags: string list }

/// Point-in-time health sample reported with each heartbeat.
type SensorHealthSample =
    { SensorId: SensorId
      SampledAt: DateTimeOffset
      CpuPercent: float
      MemoryPercent: float
      DiskPercent: float
      InterfaceUp: bool
      PacketDropPercent: float
      EventsPerSecond: float
      BufferedEvents: int64          // events held locally while central is unreachable
      ZeekRunning: bool
      SuricataRunning: bool
      Errors: string list }

type SensorHeartbeat =
    { SensorId: SensorId
      SensorName: string
      Version: string
      SentAt: DateTimeOffset
      Health: SensorHealthSample }

module SensorStatus =
    let label = function
        | SensorStatus.Online -> "online"
        | SensorStatus.Degraded -> "degraded"
        | SensorStatus.Offline -> "offline"
        | SensorStatus.Enrolling -> "enrolling"
        | SensorStatus.Disabled -> "disabled"
