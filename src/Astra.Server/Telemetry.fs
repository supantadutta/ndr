module Astra.Server.Telemetry

open System
open System.Net.Http
open System.Text
open System.Threading
open Microsoft.Extensions.Logging
open Astra.Shared

/// ============================================================================
/// Durable telemetry persistence. Normalized events are the hot in-memory
/// working set for detection/scoring; this sink additionally streams them to a
/// columnar / search backend (ClickHouse or OpenSearch) for long-term retention
/// and ad-hoc analytics. Config-gated: with neither backend configured the
/// no-op sink is used and the in-memory store remains authoritative, exactly as
/// before. Persistence is best-effort and never blocks or fails ingestion.
/// ============================================================================

type TelemetryStatus =
    { Backend: string            // "in-memory" | "clickhouse" | "opensearch"
      Endpoint: string
      Healthy: bool
      Persisted: int64
      Failed: int64
      LastError: string option
      LastFlush: DateTimeOffset option }

/// A flat, primitive-only projection of a NormalizedEvent suitable for a
/// columnar/search schema (the nested DU payload is summarized into `domain`
/// and `detail`).
type private Row =
    { event_id: string
      timestamp: string
      ingest_time: string
      sensor: string
      zone: string
      category: string
      protocol: string
      app_protocol: string
      source_ip: string
      destination_ip: string
      source_port: int
      destination_port: int
      direction: string
      bytes_in: int64
      bytes_out: int64
      domain: string
      detail: string }

let private payloadFacets (e: NormalizedEvent) : string * string =
    match e.Payload with
    | EventPayload.Dns d -> d.Query, sprintf "dns %s %s" d.QueryType d.ResponseCode
    | EventPayload.Http h -> h.Host, sprintf "http %s %s" h.Method h.Uri
    | EventPayload.Tls t -> (defaultArg t.Sni ""), sprintf "tls %s" (defaultArg t.TlsVersion "")
    | EventPayload.Smb s -> (defaultArg s.Share ""), sprintf "smb %s" (defaultArg s.Operation "")
    | EventPayload.Auth a -> "", sprintf "auth %s %s" a.AuthProtocol a.Result
    | EventPayload.IdsAlert a -> "", sprintf "ids %s" a.SignatureName
    | EventPayload.ThreatIntelMatch m -> m.Indicator, sprintf "intel %s" m.FeedName
    | _ -> "", ""

let private chTime (t: DateTimeOffset) = t.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss.fff")

let private toRow (chTimeFmt: bool) (e: NormalizedEvent) : Row =
    let domain, detail = payloadFacets e
    let fmt (t: DateTimeOffset) = if chTimeFmt then chTime t else t.ToString("o")
    { event_id = (let (EventId g) = e.EventId in string g)
      timestamp = fmt e.Timestamp
      ingest_time = fmt e.IngestTime
      sensor = e.SourceSensorName
      zone = e.SourceZone
      category = EventCategory.label e.Category
      protocol = Protocol.label e.Protocol
      app_protocol = AppProtocol.label e.ApplicationProtocol
      source_ip = e.SourceIp
      destination_ip = e.DestinationIp
      source_port = defaultArg e.SourcePort 0
      destination_port = defaultArg e.DestinationPort 0
      direction = TrafficDirection.label e.Direction
      bytes_in = e.BytesIn
      bytes_out = e.BytesOut
      domain = domain
      detail = detail }

/// Sink abstraction. Implementations must be thread-safe and non-blocking.
type ITelemetrySink =
    /// Best-effort persist a batch. Returns immediately; delivery is async.
    abstract member Persist: NormalizedEvent list -> unit
    /// Create backing schema/index if missing. Safe to call repeatedly.
    abstract member Bootstrap: unit -> unit
    abstract member Status: TelemetryStatus

/// No-op sink: the in-memory store is authoritative. Used when no backend is set.
type NullTelemetrySink() =
    interface ITelemetrySink with
        member _.Persist _ = ()
        member _.Bootstrap () = ()
        member _.Status =
            { Backend = "in-memory"; Endpoint = ""; Healthy = true
              Persisted = 0L; Failed = 0L; LastError = None; LastFlush = None }

// ---------------------------------------------------------------------------
// Shared HTTP plumbing
// ---------------------------------------------------------------------------

[<AbstractClass>]
type HttpSinkBase(backend: string, endpoint: string, logger: ILogger) =
    let http = new HttpClient(Timeout = TimeSpan.FromSeconds 10.0)
    let mutable persisted = 0L
    let mutable failed = 0L
    let mutable healthy = true
    let mutable lastError : string option = None
    let mutable lastFlush : DateTimeOffset option = None

    member _.Http = http
    member _.Backend = backend
    member _.Endpoint = endpoint

    member _.RecordSuccess(n: int) =
        Interlocked.Add(&persisted, int64 n) |> ignore
        healthy <- true
        lastError <- None
        lastFlush <- Some DateTimeOffset.UtcNow

    member _.RecordFailure(n: int, ex: exn) =
        Interlocked.Add(&failed, int64 n) |> ignore
        healthy <- false
        lastError <- Some ex.Message
        logger.LogWarning("Telemetry sink {Backend} delivery failed: {Error}", backend, ex.Message)

    member _.StatusValue =
        { Backend = backend; Endpoint = endpoint; Healthy = healthy
          Persisted = Interlocked.Read(&persisted); Failed = Interlocked.Read(&failed)
          LastError = lastError; LastFlush = lastFlush }

    /// Fire the delivery on the thread pool so ingestion never blocks.
    member this.Dispatch (count: int) (send: unit -> System.Threading.Tasks.Task) =
        let work =
            System.Func<System.Threading.Tasks.Task>(fun () ->
                (task {
                    try
                        do! send ()
                        this.RecordSuccess count
                    with ex -> this.RecordFailure(count, ex)
                }) :> System.Threading.Tasks.Task)
        System.Threading.Tasks.Task.Run(work) |> ignore

// ---------------------------------------------------------------------------
// ClickHouse (HTTP interface, JSONEachRow)
// ---------------------------------------------------------------------------

type ClickHouseTelemetrySink(url: string, database: string, table: string,
                             user: string, password: string, logger: ILogger) =
    inherit HttpSinkBase("clickhouse", url, logger)

    let qualified = sprintf "%s.%s" database table

    member private this.Exec(sql: string) =
        task {
            use req = new HttpRequestMessage(HttpMethod.Post, url)
            req.Content <- new StringContent(sql, Encoding.UTF8)
            if user <> "" then req.Headers.Add("X-ClickHouse-User", user)
            if password <> "" then req.Headers.Add("X-ClickHouse-Key", password)
            let! resp = this.Http.SendAsync req
            let! body = resp.Content.ReadAsStringAsync()
            if not resp.IsSuccessStatusCode then
                failwithf "ClickHouse HTTP %d: %s" (int resp.StatusCode) body
        }

    interface ITelemetrySink with
        member this.Bootstrap () =
            try
                (this.Exec(sprintf "CREATE DATABASE IF NOT EXISTS %s" database)).GetAwaiter().GetResult()
                let ddl =
                    sprintf "CREATE TABLE IF NOT EXISTS %s (\n" qualified +
                    "  event_id String, timestamp DateTime64(3), ingest_time DateTime64(3),\n" +
                    "  sensor String, zone String, category String, protocol String, app_protocol String,\n" +
                    "  source_ip String, destination_ip String, source_port UInt16, destination_port UInt16,\n" +
                    "  direction String, bytes_in UInt64, bytes_out UInt64, domain String, detail String\n" +
                    ") ENGINE = MergeTree ORDER BY (timestamp, source_ip)"
                (this.Exec ddl).GetAwaiter().GetResult()
                (this :> HttpSinkBase).RecordSuccess 0
                logger.LogInformation("ClickHouse telemetry ready: {Table} at {Url}", qualified, url)
            with ex ->
                (this :> HttpSinkBase).RecordFailure(0, ex)

        member this.Persist events =
            match events with
            | [] -> ()
            | _ ->
                let sb = StringBuilder()
                sb.Append(sprintf "INSERT INTO %s FORMAT JSONEachRow\n" qualified) |> ignore
                for e in events do
                    sb.AppendLine(Astra.Server.Json.serialize (toRow true e)) |> ignore
                let payload = sb.ToString()
                (this :> HttpSinkBase).Dispatch events.Length (fun () -> this.Exec payload)

        member this.Status = (this :> HttpSinkBase).StatusValue

// ---------------------------------------------------------------------------
// OpenSearch / Elasticsearch (_bulk index API)
// ---------------------------------------------------------------------------

type OpenSearchTelemetrySink(url: string, index: string, user: string, password: string, logger: ILogger) =
    inherit HttpSinkBase("opensearch", url, logger)

    let baseUrl = url.TrimEnd('/')

    member private this.Send(method: HttpMethod, path: string, body: string option) =
        task {
            use req = new HttpRequestMessage(method, baseUrl + path)
            match body with
            | Some b -> req.Content <- new StringContent(b, Encoding.UTF8, "application/json")
            | None -> ()
            if user <> "" then
                let token = Convert.ToBase64String(Encoding.UTF8.GetBytes(sprintf "%s:%s" user password))
                req.Headers.Authorization <- Headers.AuthenticationHeaderValue("Basic", token)
            let! resp = this.Http.SendAsync req
            let! respBody = resp.Content.ReadAsStringAsync()
            if not resp.IsSuccessStatusCode then
                failwithf "OpenSearch HTTP %d: %s" (int resp.StatusCode) respBody
        }

    interface ITelemetrySink with
        member this.Bootstrap () =
            try
                let mapping =
                    """{"mappings":{"properties":{
                       "timestamp":{"type":"date"},"ingest_time":{"type":"date"},
                       "source_ip":{"type":"ip"},"destination_ip":{"type":"ip"},
                       "source_port":{"type":"integer"},"destination_port":{"type":"integer"},
                       "bytes_in":{"type":"long"},"bytes_out":{"type":"long"}}}}"""
                // PUT is idempotent-ish; a 400 "already exists" is tolerated.
                try (this.Send(HttpMethod.Put, "/" + index, Some mapping)).GetAwaiter().GetResult()
                with _ -> ()
                (this :> HttpSinkBase).RecordSuccess 0
                logger.LogInformation("OpenSearch telemetry ready: index {Index} at {Url}", index, baseUrl)
            with ex ->
                (this :> HttpSinkBase).RecordFailure(0, ex)

        member this.Persist events =
            match events with
            | [] -> ()
            | _ ->
                let sb = StringBuilder()
                for e in events do
                    let row = toRow false e
                    sb.AppendLine(sprintf "{\"index\":{\"_index\":\"%s\",\"_id\":\"%s\"}}" index row.event_id) |> ignore
                    sb.AppendLine(Astra.Server.Json.serialize row) |> ignore
                let payload = sb.ToString()
                (this :> HttpSinkBase).Dispatch events.Length (fun () -> this.Send(HttpMethod.Post, "/_bulk", Some payload))

        member this.Status = (this :> HttpSinkBase).StatusValue

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Select a sink from configuration. ClickHouse takes precedence over OpenSearch
/// when both are set; with neither, the in-memory no-op sink is returned.
let create (config: Astra.Server.Config.ServerConfig) (logger: ILogger) : ITelemetrySink =
    if config.ClickHouseUrl <> "" then
        ClickHouseTelemetrySink(config.ClickHouseUrl, config.ClickHouseDatabase, config.ClickHouseTable,
                                config.ClickHouseUser, config.ClickHousePassword, logger) :> ITelemetrySink
    elif config.OpenSearchUrl <> "" then
        OpenSearchTelemetrySink(config.OpenSearchUrl, config.OpenSearchIndex,
                                config.OpenSearchUser, config.OpenSearchPassword, logger) :> ITelemetrySink
    else
        NullTelemetrySink() :> ITelemetrySink
