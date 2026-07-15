namespace Astra.Shared

open System

/// Core identifiers and enumerations shared by every Astra NDR component.
/// All types here must stay Fable-compatible: records, DUs, primitives only.

type SensorId = SensorId of Guid
type EventId = EventId of Guid
type EntityId = EntityId of Guid
type DetectionId = DetectionId of Guid
type IncidentId = IncidentId of Guid
type RuleId = RuleId of string
type UserId = UserId of Guid

[<RequireQualifiedAccess>]
type TrafficDirection =
    | InternalToInternal
    | InternalToExternal
    | ExternalToInternal
    | ExternalToExternal
    | Unknown

[<RequireQualifiedAccess>]
type TrafficLane =
    | NorthSouth
    | EastWest
    | DataCenter
    | Campus
    | RemoteUser
    | CloudWorkload
    | IotOt
    | Dmz
    | Unknown

[<RequireQualifiedAccess>]
type Severity =
    | Info
    | Low
    | Medium
    | High
    | Critical

[<RequireQualifiedAccess>]
type CollectorType =
    | NetworkSensor
    | CloudCollector
    | IdentityCollector
    | SaasCollector
    | LabReplay
    | Internal

[<RequireQualifiedAccess>]
type Protocol =
    | Tcp | Udp | Icmp | Sctp | Other of string

[<RequireQualifiedAccess>]
type AppProtocol =
    | Dns | Http | Tls | Smb | Dcerpc | Rdp | Ssh | Ldap | Kerberos | Ntlm
    | Dhcp | Smtp | Ftp | Ntp | Sip | Snmp | Mqtt | Modbus | EnipCip | Dnp3
    | Rfb | Quic | Unknown | Other of string

module Severity =
    let toInt = function
        | Severity.Info -> 0 | Severity.Low -> 25 | Severity.Medium -> 50
        | Severity.High -> 75 | Severity.Critical -> 100
    let label = function
        | Severity.Info -> "info" | Severity.Low -> "low" | Severity.Medium -> "medium"
        | Severity.High -> "high" | Severity.Critical -> "critical"
    let parse (s: string) =
        match s.ToLowerInvariant() with
        | "critical" -> Severity.Critical
        | "high" -> Severity.High
        | "medium" -> Severity.Medium
        | "low" -> Severity.Low
        | _ -> Severity.Info

module AppProtocol =
    let label = function
        | AppProtocol.Dns -> "dns" | AppProtocol.Http -> "http" | AppProtocol.Tls -> "tls"
        | AppProtocol.Smb -> "smb" | AppProtocol.Dcerpc -> "dcerpc" | AppProtocol.Rdp -> "rdp"
        | AppProtocol.Ssh -> "ssh" | AppProtocol.Ldap -> "ldap" | AppProtocol.Kerberos -> "kerberos"
        | AppProtocol.Ntlm -> "ntlm" | AppProtocol.Dhcp -> "dhcp" | AppProtocol.Smtp -> "smtp"
        | AppProtocol.Ftp -> "ftp" | AppProtocol.Ntp -> "ntp" | AppProtocol.Sip -> "sip"
        | AppProtocol.Snmp -> "snmp" | AppProtocol.Mqtt -> "mqtt" | AppProtocol.Modbus -> "modbus"
        | AppProtocol.EnipCip -> "enip_cip" | AppProtocol.Dnp3 -> "dnp3" | AppProtocol.Rfb -> "rfb"
        | AppProtocol.Quic -> "quic" | AppProtocol.Unknown -> "unknown" | AppProtocol.Other p -> p

module TrafficDirection =
    let label = function
        | TrafficDirection.InternalToInternal -> "internal_to_internal"
        | TrafficDirection.InternalToExternal -> "internal_to_external"
        | TrafficDirection.ExternalToInternal -> "external_to_internal"
        | TrafficDirection.ExternalToExternal -> "external_to_external"
        | TrafficDirection.Unknown -> "unknown"
