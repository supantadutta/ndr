module Astra.Sensor.Agent

open System
open System.IO
open System.Net.Http
open System.Text
open System.Text.Json
open System.Text.Json.Serialization
open System.Threading.Tasks
open Astra.Shared.Api

/// Sensor agent runtime: posts normalized events + heartbeats to the central
/// brain, with local buffering and retry so a brief brain outage does not lose
/// telemetry (matching the "local buffering when central is unavailable"
/// requirement). Real Zeek/Suricata deployments point this at their log dirs.

type AgentConfig =
    { ApiBase: string
      Token: string
      SensorId: string
      SensorName: string
      Version: string
      BatchSize: int }

/// Same JSON policy as the central brain so the wire formats match exactly.
let private json =
    let o = JsonSerializerOptions(PropertyNamingPolicy = JsonNamingPolicy.CamelCase)
    o.Converters.Add(
        JsonFSharpConverter(
            unionEncoding =
                (JsonUnionEncoding.ExternalTag
                 ||| JsonUnionEncoding.UnwrapOption
                 ||| JsonUnionEncoding.UnwrapFieldlessTags
                 ||| JsonUnionEncoding.UnwrapSingleCaseUnions)))
    o

type Agent(config: AgentConfig) =
    let http = new HttpClient(Timeout = TimeSpan.FromSeconds 30.0)
    // In-memory local buffer; a production build would spill to disk.
    let buffer = System.Collections.Generic.Queue<IngestEventDto>()

    do http.DefaultRequestHeaders.Add("X-Astra-Sensor-Token", config.Token)

    let postJson (path: string) (payload: 'T) =
        task {
            let body = JsonSerializer.Serialize<'T>(payload, json)
            use content = new StringContent(body, Encoding.UTF8, "application/json")
            let! resp = http.PostAsync(config.ApiBase + path, content)
            let! text = resp.Content.ReadAsStringAsync()
            return resp.IsSuccessStatusCode, int resp.StatusCode, text
        }

    /// Send a heartbeat with a best-effort local health snapshot.
    member _.SendHeartbeat(?errors: string list) =
        task {
            let hb =
                { SensorId = config.SensorId
                  SensorName = config.SensorName
                  Version = config.Version
                  CpuPercent = 0.0
                  MemoryPercent = 0.0
                  DiskPercent = 0.0
                  InterfaceUp = true
                  PacketDropPercent = 0.0
                  EventsPerSecond = 0.0
                  BufferedEvents = int64 buffer.Count
                  ZeekRunning = true
                  SuricataRunning = true
                  Errors = defaultArg errors [] }
            try
                let! (ok, code, _) = postJson Routes.ingestHeartbeat hb
                return ok, code
            with ex ->
                eprintfn "heartbeat failed: %s" ex.Message
                return false, 0
        }

    /// Flush buffered events in batches. On failure, events stay buffered.
    member _.Flush() =
        task {
            let mutable accepted = 0
            let mutable keepGoing = buffer.Count > 0
            while keepGoing do
                let batch = ResizeArray<IngestEventDto>()
                while batch.Count < config.BatchSize && buffer.Count > 0 do
                    batch.Add(buffer.Dequeue())
                let req = { SensorId = config.SensorId; SensorName = config.SensorName; Events = List.ofSeq batch }
                try
                    let! (ok, _, text) = postJson Routes.ingestEvents req
                    if ok then
                        let resp = JsonSerializer.Deserialize<IngestBatchResponse>(text, json)
                        accepted <- accepted + resp.Accepted
                    else
                        // re-buffer on failure and stop this cycle
                        for e in batch do buffer.Enqueue e
                        keepGoing <- false
                with ex ->
                    eprintfn "flush failed, re-buffering %d events: %s" batch.Count ex.Message
                    for e in batch do buffer.Enqueue e
                    keepGoing <- false
                if buffer.Count = 0 then keepGoing <- false
            return accepted
        }

    member _.Enqueue(events: IngestEventDto seq) = for e in events do buffer.Enqueue e
    member _.BufferedCount = buffer.Count

    interface IDisposable with
        member _.Dispose() = http.Dispose()

// ---------------------------------------------------------------------------
// Log directory readers
// ---------------------------------------------------------------------------

/// Parse every Zeek + Suricata log found under a directory (one-shot / replay).
let readLogDir (dir: string) : IngestEventDto list =
    if not (Directory.Exists dir) then []
    else
        let zeek =
            Directory.GetFiles(dir, "*.log", SearchOption.AllDirectories)
            |> Array.filter (fun f ->
                let n = Path.GetFileName f
                not (n.StartsWith "eve") && not (n = "fast.log"))
            |> Array.collect (fun f -> File.ReadAllText f |> Zeek.parseText |> Array.ofList)
            |> Array.toList
        let eve =
            Directory.GetFiles(dir, "eve*.json", SearchOption.AllDirectories)
            |> Array.collect (fun f -> File.ReadAllText f |> Suricata.parseEve |> Array.ofList)
            |> Array.toList
        let fast =
            Directory.GetFiles(dir, "fast.log", SearchOption.AllDirectories)
            |> Array.collect (fun f -> File.ReadAllText f |> Suricata.parseFastLog |> Array.ofList)
            |> Array.toList
        zeek @ eve @ fast

/// Tail a growing file, yielding new events via a callback. Used in live mode
/// for a Suricata eve.json or a Zeek log that Zeek appends to.
let tailFile (path: string) (isEve: bool) (onEvents: IngestEventDto list -> unit) (token: Threading.CancellationToken) =
    task {
        let mutable lastLen = 0L
        // For Zeek TSV we must re-read headers, so we re-parse the whole file on
        // change; for EVE (line-delimited) we parse only appended lines.
        while not token.IsCancellationRequested do
            try
                if File.Exists path then
                    let len = FileInfo(path).Length
                    if len > lastLen then
                        if isEve then
                            use fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)
                            fs.Seek(lastLen, SeekOrigin.Begin) |> ignore
                            use reader = new StreamReader(fs)
                            let! chunk = reader.ReadToEndAsync()
                            chunk.Split('\n') |> Array.toList |> List.choose Suricata.parseEveLine |> onEvents
                        else
                            let events = File.ReadAllText path |> Zeek.parseText
                            onEvents events
                        lastLen <- len
            with ex -> eprintfn "tail error on %s: %s" path ex.Message
            do! Task.Delay(2000, token)
    }
