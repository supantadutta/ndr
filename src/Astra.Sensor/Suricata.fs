module Astra.Sensor.Suricata

open System
open System.Text.Json
open Astra.Shared.Api

/// Parsers for Suricata output:
///   * EVE JSON  (one JSON object per line; event_type = alert|dns|http|tls|flow|…)
///   * fast.log  (single-line text alerts)
///
/// Suricata is a first-class source. EVE alerts carry signature id/rev/category
/// /severity which the central brain lifts into a typed IdsAlert payload and
/// correlates with behavioral detections.

let private tryStr (el: JsonElement) (name: string) =
    match el.TryGetProperty name with
    | true, v when v.ValueKind = JsonValueKind.String -> Some (v.GetString())
    | _ -> None

let private tryInt (el: JsonElement) (name: string) =
    match el.TryGetProperty name with
    | true, v when v.ValueKind = JsonValueKind.Number -> Some (v.GetInt64())
    | _ -> None

let private tryObj (el: JsonElement) (name: string) =
    match el.TryGetProperty name with
    | true, v when v.ValueKind = JsonValueKind.Object -> Some v
    | _ -> None

let private isoTime (el: JsonElement) =
    match tryStr el "timestamp" with
    | Some t ->
        match DateTimeOffset.TryParse t with
        | true, d -> d.ToString("o")
        | _ -> DateTimeOffset.UtcNow.ToString("o")
    | None -> DateTimeOffset.UtcNow.ToString("o")

let private baseFrom (el: JsonElement) category app extraFields : IngestEventDto =
    { Timestamp = isoTime el
      ObservedTime = isoTime el
      Category = category
      Protocol = (tryStr el "proto" |> Option.defaultValue "-").ToLowerInvariant()
      ApplicationProtocol = app
      SourceIp = tryStr el "src_ip" |> Option.defaultValue ""
      DestinationIp = tryStr el "dest_ip" |> Option.defaultValue ""
      SourcePort = tryInt el "src_port" |> Option.map int
      DestinationPort = tryInt el "dest_port" |> Option.map int
      Hostname = None
      Username = None
      BytesIn = 0L
      BytesOut = 0L
      PacketsIn = 0L
      PacketsOut = 0L
      DurationMs = None
      Fields = Map.ofList (("raw_ref", sprintf "suricata://%s" (tryStr el "flow_id" |> Option.defaultValue (isoTime el))) :: extraFields) }

let private mapAlert (el: JsonElement) : IngestEventDto option =
    match tryObj el "alert" with
    | None -> None
    | Some alert ->
        let fields =
            [ "signature", (tryStr alert "signature" |> Option.defaultValue "unknown")
              "signature_id", (tryInt alert "signature_id" |> Option.map string |> Option.defaultValue "0")
              "signature_rev", (tryInt alert "rev" |> Option.map string |> Option.defaultValue "0")
              "ids_category", (tryStr alert "category" |> Option.defaultValue "")
              "ids_severity", (tryInt alert "severity" |> Option.map string |> Option.defaultValue "3")
              "rule_source", (tryStr el "rule" |> Option.defaultValue "suricata") ]
        Some (baseFrom el "ids_signature_alert" "-" fields)

let private mapDns (el: JsonElement) : IngestEventDto option =
    match tryObj el "dns" with
    | None -> None
    | Some dns ->
        // Only index queries (type = query) to avoid double-counting responses.
        match tryStr dns "type" with
        | Some "query" | None ->
            let fields =
                [ "query", (tryStr dns "rrname" |> Option.defaultValue "")
                  "query_type", (tryStr dns "rrtype" |> Option.defaultValue "A")
                  "rcode", (tryStr dns "rcode" |> Option.defaultValue "NOERROR") ]
            Some (baseFrom el "dns" "dns" fields)
        | _ -> None

let private mapHttp (el: JsonElement) : IngestEventDto option =
    match tryObj el "http" with
    | None -> None
    | Some http ->
        let fields =
            [ "method", (tryStr http "http_method" |> Option.defaultValue "GET")
              "host", (tryStr http "hostname" |> Option.defaultValue "")
              "uri", (tryStr http "url" |> Option.defaultValue "/")
              "user_agent", (tryStr http "http_user_agent" |> Option.defaultValue "")
              "status_code", (tryInt http "status" |> Option.map string |> Option.defaultValue "") ]
        Some (baseFrom el "http" "http" fields)

let private mapTls (el: JsonElement) : IngestEventDto option =
    match tryObj el "tls" with
    | None -> None
    | Some tls ->
        let fields =
            [ "sni", (tryStr tls "sni" |> Option.defaultValue "")
              "tls_version", (tryStr tls "version" |> Option.defaultValue "")
              "cert_subject", (tryStr tls "subject" |> Option.defaultValue "")
              "cert_issuer", (tryStr tls "issuerdn" |> Option.defaultValue "")
              "ja3", (tryObj tls "ja3" |> Option.bind (fun j -> tryStr j "hash") |> Option.defaultValue "")
              "ja3s", (tryObj tls "ja3s" |> Option.bind (fun j -> tryStr j "hash") |> Option.defaultValue "") ]
        Some (baseFrom el "tls" "tls" fields)

let private mapFlow (el: JsonElement) : IngestEventDto option =
    match tryObj el "flow" with
    | None -> Some (baseFrom el "network_connection" "-" [])
    | Some flow ->
        let dto = baseFrom el "network_connection" "-" []
        { dto with
            BytesOut = tryInt flow "bytes_toserver" |> Option.defaultValue 0L
            BytesIn = tryInt flow "bytes_toclient" |> Option.defaultValue 0L
            PacketsOut = tryInt flow "pkts_toserver" |> Option.defaultValue 0L
            PacketsIn = tryInt flow "pkts_toclient" |> Option.defaultValue 0L }
        |> Some

/// Parse one EVE JSON line into an ingest event (if the event_type is mapped).
let parseEveLine (line: string) : IngestEventDto option =
    if String.IsNullOrWhiteSpace line then None
    else
        try
            use doc = JsonDocument.Parse line
            let el = doc.RootElement
            match tryStr el "event_type" with
            | Some "alert" -> mapAlert el
            | Some "dns" -> mapDns el
            | Some "http" -> mapHttp el
            | Some "tls" -> mapTls el
            | Some "flow" -> mapFlow el
            | _ -> None
        with _ -> None   // malformed line: skip, never crash the sensor

/// Parse an EVE JSON file's text (newline-delimited JSON).
let parseEve (text: string) : IngestEventDto list =
    text.Replace("\r\n", "\n").Split('\n')
    |> Array.toList
    |> List.choose parseEveLine
    |> List.filter (fun e -> e.SourceIp <> "" && e.DestinationIp <> "")

/// Parse a Suricata fast.log line, e.g.:
/// 03/09/2026-06:00:00.123456  [**] [1:2013028:6] ET POLICY ... [**]
///   [Classification: ...] [Priority: 1] {TCP} 10.0.0.5:1234 -> 203.0.113.9:443
let private fastLogRegex =
    Text.RegularExpressions.Regex(
        @"\[\*\*\]\s\[(\d+):(\d+):(\d+)\]\s(.+?)\s\[\*\*\].*?\[Priority:\s(\d+)\].*?\{(\w+)\}\s([\d\.]+):?(\d+)?\s->\s([\d\.]+):?(\d+)?",
        Text.RegularExpressions.RegexOptions.Compiled)

let parseFastLine (line: string) : IngestEventDto option =
    let m = fastLogRegex.Match line
    if not m.Success then None
    else
        let grp (i: int) = m.Groups.[i].Value
        let portOpt (i: int) = match Int32.TryParse (grp i) with | true, n -> Some n | _ -> None
        Some
            { Timestamp = DateTimeOffset.UtcNow.ToString("o")
              ObservedTime = DateTimeOffset.UtcNow.ToString("o")
              Category = "ids_signature_alert"
              Protocol = (grp 6).ToLowerInvariant()
              ApplicationProtocol = "-"
              SourceIp = grp 7
              DestinationIp = grp 9
              SourcePort = portOpt 8
              DestinationPort = portOpt 10
              Hostname = None
              Username = None
              BytesIn = 0L; BytesOut = 0L; PacketsIn = 0L; PacketsOut = 0L
              DurationMs = None
              Fields =
                Map.ofList
                    [ "signature", grp 4
                      "signature_id", grp 2
                      "signature_rev", grp 3
                      "ids_severity", grp 5
                      "rule_source", "suricata-fast" ] }

let parseFastLog (text: string) : IngestEventDto list =
    text.Replace("\r\n", "\n").Split('\n')
    |> Array.toList
    |> List.choose parseFastLine
