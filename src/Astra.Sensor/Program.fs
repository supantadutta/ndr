module Astra.Sensor.Program

open System
open System.Threading
open Astra.Sensor.Agent

/// Astra NDR sensor agent CLI.
///
/// Modes:
///   replay   parse a directory of Zeek/Suricata logs once and ship them
///            (offline analysis / PCAP-replay output / lab)
///   live     watch a Zeek log dir + a Suricata eve.json and ship as they grow
///            (real deployment tailing live Zeek/Suricata output)
///
/// A real sensor runs Zeek + Suricata on a SPAN/TAP interface writing to a log
/// directory; this agent normalizes that output and posts it to the brain.

let private arg (args: string[]) name fallback =
    args
    |> Array.tryFindIndex (fun a -> a = name)
    |> Option.bind (fun i -> if i + 1 < args.Length then Some args.[i + 1] else None)
    |> Option.defaultValue fallback

let private usage () =
    printfn "Astra NDR sensor agent"
    printfn ""
    printfn "Usage:"
    printfn "  astra-sensor replay --log-dir <dir> [--api URL] [--token T] [--sensor-id GUID] [--name N]"
    printfn "  astra-sensor live   --log-dir <dir> --eve <eve.json> [--api URL] [--token T] ..."
    printfn ""
    printfn "Options:"
    printfn "  --api        central brain base URL   (default http://localhost:5170)"
    printfn "  --token      sensor API token         (default dev-sensor-token-change-me)"
    printfn "  --sensor-id  sensor GUID              (default 44444444-4444-4444-4444-444444444444)"
    printfn "  --name       sensor name              (default sensor-field-01)"
    printfn "  --log-dir    Zeek/Suricata log directory"
    printfn "  --eve        Suricata eve.json path   (live mode)"
    printfn "  --heartbeat  seconds between heartbeats (default 30)"

[<EntryPoint>]
let main argv =
    if argv.Length = 0 || argv.[0] = "-h" || argv.[0] = "--help" then usage (); 0
    else
    let mode = argv.[0]
    let config =
        { ApiBase = arg argv "--api" "http://localhost:5170"
          Token = arg argv "--token" "dev-sensor-token-change-me"
          SensorId = arg argv "--sensor-id" "44444444-4444-4444-4444-444444444444"
          SensorName = arg argv "--name" "sensor-field-01"
          Version = "1.0.0"
          BatchSize = 500 }
    let logDir = arg argv "--log-dir" ""
    use agent = new Agent(config)

    match mode with
    | "replay" ->
        if logDir = "" then usage (); 1
        else
            printfn "Astra sensor (replay): reading %s" logDir
            let raw = readLogDir logDir
            // Rebase timestamps so the newest event lands at "now" (preserving
            // relative spacing). This makes replaying an old capture's logs light
            // up real-time detections. Use --preserve-time to keep original times.
            let preserve = Array.contains "--preserve-time" argv
            let events =
                if preserve || raw.IsEmpty then raw
                else
                    let parse (s: string) = match DateTimeOffset.TryParse s with | true, d -> Some d | _ -> None
                    let times = raw |> List.choose (fun e -> parse e.Timestamp)
                    if times.IsEmpty then raw
                    else
                        let newest = List.max times
                        let shift = DateTimeOffset.UtcNow - newest
                        raw |> List.map (fun e ->
                            match parse e.Timestamp, parse e.ObservedTime with
                            | Some t, Some o -> { e with Timestamp = (t + shift).ToString("o"); ObservedTime = (o + shift).ToString("o") }
                            | _ -> e)
            printfn "Parsed %d events from Zeek/Suricata logs%s" events.Length (if preserve then "" else " (timestamps rebased to now)")
            let task =
                task {
                    let! (hbOk, _) = agent.SendHeartbeat()
                    printfn "Heartbeat: %s" (if hbOk then "acknowledged" else "FAILED (is the brain up?)")
                    agent.Enqueue events
                    let! accepted = agent.Flush()
                    printfn "Shipped %d events (%d buffered/unsent)" accepted agent.BufferedCount
                }
            task.GetAwaiter().GetResult()
            0
    | "live" ->
        let eve = arg argv "--eve" ""
        let hbSec = arg argv "--heartbeat" "30" |> int
        printfn "Astra sensor (live): log-dir=%s eve=%s -> %s" logDir eve config.ApiBase
        use cts = new CancellationTokenSource()
        Console.CancelKeyPress.Add(fun a -> a.Cancel <- true; cts.Cancel())

        let onEvents (events: Astra.Shared.Api.IngestEventDto list) =
            if not events.IsEmpty then
                agent.Enqueue events
                (agent.Flush()).GetAwaiter().GetResult() |> ignore

        let tasks = System.Collections.Generic.List<Tasks.Task>()
        // periodic heartbeat
        tasks.Add(task {
            while not cts.Token.IsCancellationRequested do
                let! _ = agent.SendHeartbeat()
                do! Tasks.Task.Delay(TimeSpan.FromSeconds(float hbSec), cts.Token)
        })
        if eve <> "" then tasks.Add(tailFile eve true onEvents cts.Token)
        if logDir <> "" then
            // watch each known Zeek log in the dir
            for name in [ "conn.log"; "dns.log"; "http.log"; "ssl.log"; "smb_files.log"; "kerberos.log"; "dce_rpc.log"; "ntlm.log"; "dhcp.log" ] do
                tasks.Add(tailFile (IO.Path.Combine(logDir, name)) false onEvents cts.Token)
        printfn "Watching for telemetry (Ctrl-C to stop)…"
        try Tasks.Task.WaitAll(tasks.ToArray()) with :? OperationCanceledException | :? AggregateException -> ()
        printfn "Sensor stopped."
        0
    | _ -> usage (); 1
