module Astra.Server.Hunt

open System
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Threat-hunting metadata search over the normalized-event window.
///
/// A hunt query is a typed set of AND-ed field predicates plus a time range.
/// The engine evaluates it over the in-memory event window (Phase 4); the same
/// predicate model maps onto SQL/ClickHouse when the telemetry tier lands.
/// Aggregations power the hunt templates (top talkers, rare SNI, etc).
/// ============================================================================

type HuntPredicate =
    { Field: string      // src_ip | dst_ip | domain | sni | user_agent | account | port | protocol | app | category | direction
      Op: string         // eq | contains | gt | lt
      Value: string }

type HuntQuery =
    { Predicates: HuntPredicate list
      WindowMinutes: int
      Limit: int }

// ---------------------------------------------------------------------------
// Field extraction from a normalized event
// ---------------------------------------------------------------------------
let private fieldValue (e: NormalizedEvent) (field: string) : string option =
    match field with
    | "src_ip" -> Some e.SourceIp
    | "dst_ip" -> Some e.DestinationIp
    | "hostname" -> e.Hostname
    | "account" -> e.AccountName
    | "port" -> e.DestinationPort |> Option.map string
    | "src_port" -> e.SourcePort |> Option.map string
    | "protocol" -> Some (match e.Protocol with Protocol.Tcp -> "tcp" | Protocol.Udp -> "udp" | Protocol.Icmp -> "icmp" | Protocol.Sctp -> "sctp" | Protocol.Other o -> o)
    | "app" -> Some (AppProtocol.label e.ApplicationProtocol)
    | "category" -> Some (EventCategory.label e.Category)
    | "direction" -> Some (TrafficDirection.label e.Direction)
    | "bytes_out" -> Some (string e.BytesOut)
    | "bytes_in" -> Some (string e.BytesIn)
    | "domain" | "sni" | "query" | "user_agent" | "host" | "uri" | "share" | "signature" ->
        match e.Payload with
        | EventPayload.Dns d -> (match field with "domain" | "query" -> Some d.Query | _ -> None)
        | EventPayload.Tls t -> (match field with "sni" | "domain" -> t.Sni | _ -> None)
        | EventPayload.Http h -> (match field with "host" | "domain" -> Some h.Host | "uri" -> Some h.Uri | "user_agent" -> h.UserAgent | _ -> None)
        | EventPayload.Smb s -> (match field with "share" -> s.Share | _ -> None)
        | EventPayload.IdsAlert a -> (match field with "signature" -> Some a.SignatureName | _ -> None)
        | _ -> None
    | _ -> None

let private matchesPredicate (e: NormalizedEvent) (p: HuntPredicate) : bool =
    match fieldValue e p.Field with
    | None -> false
    | Some v ->
        match p.Op with
        | "eq" -> String.Equals(v, p.Value, StringComparison.OrdinalIgnoreCase)
        | "contains" -> v.IndexOf(p.Value, StringComparison.OrdinalIgnoreCase) >= 0
        | "gt" -> (match Double.TryParse v, Double.TryParse p.Value with (true, a), (true, b) -> a > b | _ -> false)
        | "lt" -> (match Double.TryParse v, Double.TryParse p.Value with (true, a), (true, b) -> a < b | _ -> false)
        | _ -> false

// ---------------------------------------------------------------------------
// Result shape
// ---------------------------------------------------------------------------
type HuntRow =
    { Timestamp: DateTimeOffset
      Category: string
      Protocol: string
      App: string
      SourceIp: string
      DestinationIp: string
      DestinationPort: int option
      BytesOut: int64
      BytesIn: int64
      Detail: string }

type HuntAggBucket = { Key: string; Count: int; Bytes: int64 }

type HuntResult =
    { Total: int
      Rows: HuntRow list
      TopDestinations: HuntAggBucket list
      TopSources: HuntAggBucket list }

let private detailOf (e: NormalizedEvent) =
    match e.Payload with
    | EventPayload.Dns d -> sprintf "dns %s %s" d.QueryType d.Query
    | EventPayload.Tls t -> sprintf "tls sni=%s" (defaultArg t.Sni "-")
    | EventPayload.Http h -> sprintf "http %s %s%s" h.Method h.Host h.Uri
    | EventPayload.Smb s -> sprintf "smb %s %s" (defaultArg s.Operation "-") (defaultArg s.Share "-")
    | EventPayload.Auth a -> sprintf "auth %s %s" a.AuthProtocol a.Result
    | EventPayload.IdsAlert a -> sprintf "ids sid=%d %s" a.SignatureId a.SignatureName
    | _ -> ""

let private toRow (e: NormalizedEvent) : HuntRow =
    { Timestamp = e.Timestamp; Category = EventCategory.label e.Category
      Protocol = (match e.Protocol with Protocol.Tcp -> "tcp" | Protocol.Udp -> "udp" | Protocol.Icmp -> "icmp" | Protocol.Sctp -> "sctp" | Protocol.Other o -> o)
      App = AppProtocol.label e.ApplicationProtocol
      SourceIp = e.SourceIp; DestinationIp = e.DestinationIp; DestinationPort = e.DestinationPort
      BytesOut = e.BytesOut; BytesIn = e.BytesIn; Detail = detailOf e }

/// Execute a hunt query against the store's recent event window.
let run (store: AstraStore) (query: HuntQuery) : HuntResult =
    let window = store.RecentEvents(TimeSpan.FromMinutes(float (max 1 query.WindowMinutes)))
    let matched =
        window
        |> List.filter (fun e -> query.Predicates |> List.forall (matchesPredicate e))
    let limit = if query.Limit <= 0 then 200 else min 1000 query.Limit

    let agg (keyOf: NormalizedEvent -> string) =
        matched
        |> List.groupBy keyOf
        |> List.map (fun (k, evts) -> { Key = k; Count = evts.Length; Bytes = evts |> List.sumBy (fun e -> e.BytesOut) })
        |> List.sortByDescending (fun b -> b.Count)
        |> List.truncate 10

    { Total = matched.Length
      Rows = matched |> List.sortByDescending (fun e -> e.Timestamp) |> List.truncate limit |> List.map toRow
      TopDestinations = agg (fun e -> e.DestinationIp)
      TopSources = agg (fun e -> e.SourceIp) }

// ---------------------------------------------------------------------------
// Hunt templates: named canned queries
// ---------------------------------------------------------------------------
type HuntTemplate = { Id: string; Name: string; Description: string; Query: HuntQuery }

let templates : HuntTemplate list =
    [ { Id = "top_external"; Name = "Top external destinations"
        Description = "All internal→external traffic in the window, aggregated by destination."
        Query = { Predicates = [ { Field = "direction"; Op = "eq"; Value = "internal_to_external" } ]; WindowMinutes = 60; Limit = 200 } }
      { Id = "dns_all"; Name = "DNS activity"
        Description = "All DNS queries — pivot on domain to find tunneling."
        Query = { Predicates = [ { Field = "category"; Op = "eq"; Value = "dns" } ]; WindowMinutes = 60; Limit = 300 } }
      { Id = "smb_writes"; Name = "SMB file activity"
        Description = "SMB file operations — spot admin-share and ransomware-style writes."
        Query = { Predicates = [ { Field = "category"; Op = "eq"; Value = "smb_file" } ]; WindowMinutes = 60; Limit = 200 } }
      { Id = "rdp_ssh"; Name = "Remote access (RDP/SSH)"
        Description = "Lateral remote-access sessions over 3389/22."
        Query = { Predicates = [ { Field = "port"; Op = "eq"; Value = "3389" } ]; WindowMinutes = 120; Limit = 200 } }
      { Id = "ids_alerts"; Name = "IDS signature alerts"
        Description = "All Suricata signature matches in the window."
        Query = { Predicates = [ { Field = "category"; Op = "eq"; Value = "ids_signature_alert" } ]; WindowMinutes = 120; Limit = 200 } } ]
