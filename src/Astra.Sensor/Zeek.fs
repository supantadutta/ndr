module Astra.Sensor.Zeek

open System
open Astra.Shared.Api

/// Parser for Zeek TSV logs (conn/dns/http/ssl/smb/dce_rpc/kerberos/ntlm/dhcp).
/// A Zeek log file starts with #-prefixed header lines; `#fields` names the
/// columns and `#path` names the log type. Each data row is tab-separated and
/// uses `-` for unset values.

type ZeekLog =
    { Path: string
      Fields: string[]
      Separator: string
      UnsetField: string
      Rows: string[][] }

/// Parse a Zeek log file's text into a structured log (header + typed rows).
let parseFile (text: string) : ZeekLog option =
    let lines = text.Replace("\r\n", "\n").Split('\n')
    let mutable path = ""
    let mutable fields : string[] = [||]
    let mutable sep = "\t"
    let mutable unset = "-"
    let rows = ResizeArray<string[]>()
    for line in lines do
        if line.StartsWith "#separator" then
            // value is like "\x09"
            let v = line.Substring("#separator".Length).Trim()
            sep <- if v = "\\x09" then "\t" else Text.RegularExpressions.Regex.Unescape v
        elif line.StartsWith "#unset_field" then
            unset <- line.Split('\t') |> Array.tryLast |> Option.defaultValue "-"
        elif line.StartsWith "#path" then
            path <- line.Split('\t') |> Array.tryLast |> Option.defaultValue ""
        elif line.StartsWith "#fields" then
            fields <- line.Split(sep.[0]) |> Array.skip 1
        elif line.StartsWith "#" then ()
        elif line.Trim() = "" then ()
        else
            rows.Add(line.Split(sep.[0]))
    if fields.Length = 0 || path = "" then None
    else Some { Path = path; Fields = fields; Separator = sep; UnsetField = unset; Rows = rows.ToArray() }

/// A row as a field-name → value map, dropping unset (`-`) values.
let rowMap (log: ZeekLog) (row: string[]) : Map<string, string> =
    Array.zip (Array.truncate row.Length log.Fields) (Array.truncate log.Fields.Length row)
    |> Array.choose (fun (k, v) -> if v = log.UnsetField || v = "" then None else Some (k, v))
    |> Map.ofArray

// ---------------------------------------------------------------------------
// Field helpers
// ---------------------------------------------------------------------------
let private g (m: Map<string, string>) k = Map.tryFind k m
let private gs m k = g m k |> Option.defaultValue ""
let private gi m k = g m k |> Option.bind (fun v -> match Int32.TryParse v with | true, n -> Some n | _ -> None)
let private gl m k = g m k |> Option.bind (fun v -> match Int64.TryParse v with | true, n -> Some n | _ -> None) |> Option.defaultValue 0L
let private gf m k = g m k |> Option.bind (fun v -> match Double.TryParse(v, Globalization.CultureInfo.InvariantCulture) with | true, n -> Some n | _ -> None)

/// Zeek `ts` is epoch seconds (float). Convert to ISO-8601.
let private tsIso m =
    match gf m "ts" with
    | Some epoch -> DateTimeOffset.FromUnixTimeMilliseconds(int64 (epoch * 1000.0)).ToString("o")
    | None -> DateTimeOffset.UtcNow.ToString("o")

let private isAdminShare (share: string) =
    let s = share.ToUpperInvariant()
    s.Contains "ADMIN$" || s.Contains "C$" || s.Contains "IPC$"

/// Build an IngestEventDto with the common 5-tuple/volume fields filled from
/// the standard Zeek `id.*` columns, then overlaid with category-specific fields.
let private baseDto (m: Map<string, string>) category app extraFields : IngestEventDto =
    { Timestamp = tsIso m
      ObservedTime = tsIso m
      Category = category
      Protocol = gs m "proto"
      ApplicationProtocol = app
      SourceIp = gs m "id.orig_h"
      DestinationIp = gs m "id.resp_h"
      SourcePort = gi m "id.orig_p"
      DestinationPort = gi m "id.resp_p"
      Hostname = None
      Username = None
      BytesIn = gl m "resp_bytes"
      BytesOut = gl m "orig_bytes"
      PacketsIn = gl m "resp_pkts"
      PacketsOut = gl m "orig_pkts"
      DurationMs = gf m "duration" |> Option.map (fun d -> int64 (d * 1000.0))
      Fields = Map.ofList (("raw_ref", sprintf "zeek://%s/%s" (gs m "uid") (tsIso m)) :: extraFields) }

// ---------------------------------------------------------------------------
// Per-log mappers → IngestEventDto
// ---------------------------------------------------------------------------
let private mapConn m = baseDto m "network_connection" "-" [ "service", gs m "service"; "conn_state", gs m "conn_state" ]

let private mapDns m =
    baseDto m "dns" "dns"
        [ "query", gs m "query"; "query_type", gs m "qtype_name"; "rcode", gs m "rcode_name"; "answers", gs m "answers" ]

let private mapHttp m =
    baseDto m "http" "http"
        [ "method", gs m "method"; "host", gs m "host"; "uri", gs m "uri"
          "user_agent", gs m "user_agent"; "status_code", gs m "status_code" ]

let private mapSsl m =
    baseDto m "tls" "tls"
        [ "sni", gs m "server_name"; "tls_version", gs m "version"; "cipher", gs m "cipher"
          "cert_subject", gs m "subject"; "cert_issuer", gs m "issuer"; "ja3", gs m "ja3"; "ja3s", gs m "ja3s" ]

let private mapSmbFiles m =
    let action = gs m "action"
    let op =
        if action.Contains "WRITE" then "write"
        elif action.Contains "READ" then "read"
        elif action.Contains "OPEN" then "open"
        elif action.Contains "DELETE" then "delete"
        else action.ToLowerInvariant()
    baseDto m "smb_file" "smb"
        [ "share", gs m "name"; "path", gs m "path"; "operation", op
          "is_admin_share", (if isAdminShare (gs m "name" + gs m "path") then "true" else "false") ]

let private mapSmbMapping m =
    baseDto m "smb_session" "smb"
        [ "share", gs m "path"; "service", gs m "service"
          "is_admin_share", (if isAdminShare (gs m "path") then "true" else "false") ]

let private mapDceRpc m =
    baseDto m "dcerpc" "dcerpc"
        [ "named_pipe", gs m "named_pipe"; "endpoint", gs m "endpoint"; "operation", gs m "operation" ]

let private mapKerberos m =
    baseDto m "kerberos" "kerberos"
        [ "auth_protocol", "kerberos"; "target_service", gs m "service"; "account", gs m "client"
          "result", (if gs m "success" = "T" then "success" else "failure")
          "failure_reason", gs m "error_msg"
          "is_privileged", (if (gs m "service").ToLowerInvariant().Contains "admin" then "true" else "false") ]

let private mapNtlm m =
    baseDto m "ntlm" "ntlm"
        [ "auth_protocol", "ntlm"; "account", gs m "username"; "domain", gs m "domainname"
          "result", (if gs m "success" = "T" then "success" else "failure") ]

let private mapDhcp m =
    baseDto m "dhcp" "dhcp"
        [ "assigned_ip", gs m "assigned_addr"; "requested_ip", gs m "requested_addr"
          "client_hostname", gs m "host_name"; "lease", gs m "lease_time" ]

/// Convert a parsed Zeek log into normalized ingest DTOs.
let toEvents (log: ZeekLog) : IngestEventDto list =
    let mapper =
        match log.Path with
        | "conn" -> Some mapConn
        | "dns" -> Some mapDns
        | "http" -> Some mapHttp
        | "ssl" -> Some mapSsl
        | "smb_files" -> Some mapSmbFiles
        | "smb_mapping" -> Some mapSmbMapping
        | "dce_rpc" -> Some mapDceRpc
        | "kerberos" -> Some mapKerberos
        | "ntlm" -> Some mapNtlm
        | "dhcp" -> Some mapDhcp
        | _ -> None
    match mapper with
    | None -> []
    | Some f ->
        log.Rows
        |> Array.toList
        |> List.map (fun row -> rowMap log row |> f)
        |> List.filter (fun e -> e.SourceIp <> "" && e.DestinationIp <> "")

/// Parse a single Zeek log file's text into ingest events.
let parseText (text: string) : IngestEventDto list =
    match parseFile text with Some log -> toEvents log | None -> []
