module Astra.Server.HttpHandlers

open System
open Microsoft.AspNetCore.Http
open Giraffe
open Astra.Shared
open Astra.Shared.Api
open Astra.Server.Store
open Astra.Server.Ingestion

/// Giraffe HTTP handlers. JSON is emitted via System.Text.Json using the shared
/// options so every response matches what the Fable client's Thoth decoders expect.

let private json (value: 'T) : HttpHandler =
    fun next ctx ->
        ctx.SetContentType "application/json; charset=utf-8"
        let payload = Astra.Server.Json.serialize value
        (setBodyFromString payload) next ctx

let private badRequest (msg: string) : HttpHandler =
    setStatusCode 400 >=> json { Error = "bad_request"; Detail = msg }

let private queryInt (ctx: HttpContext) name fallback =
    match ctx.TryGetQueryStringValue name with
    | Some v -> match Int32.TryParse v with | true, n -> n | _ -> fallback
    | None -> fallback

// ---------------------------------------------------------------- read models
let healthHandler : HttpHandler =
    json {| status = "ok"; service = "astra-ndr"; time = DateTimeOffset.UtcNow.ToString("o") |}

let dashboardHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (Astra.Server.Mappers.dashboardSummary store) next ctx

let entityQueueHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        let page = queryInt ctx "page" 1
        let pageSize = min 200 (queryInt ctx "pageSize" 50)
        json (Astra.Server.Mappers.entityQueue store page pageSize) next ctx

let entityDetailHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            match store.TryGetEntity(EntityId g) with
            | Some e -> json (Astra.Server.Mappers.entityDetail store e) next ctx
            | None -> (setStatusCode 404 >=> json { Error = "not_found"; Detail = "entity not found" }) next ctx
        | _ -> badRequest "invalid entity id" next ctx

let detectionsHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        let page = queryInt ctx "page" 1
        let pageSize = min 200 (queryInt ctx "pageSize" 50)
        json (Astra.Server.Mappers.detectionPage store page pageSize) next ctx

let detectionDetailHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            match store.TryGetDetection(DetectionId g) with
            | Some d -> json (Astra.Server.Mappers.detectionDetail store d) next ctx
            | None -> (setStatusCode 404 >=> json { Error = "not_found"; Detail = "detection not found" }) next ctx
        | _ -> badRequest "invalid detection id" next ctx

let incidentsHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        let items =
            store.Incidents
            |> List.sortByDescending (fun i -> i.Urgency)
            |> List.map (Astra.Server.Mappers.incidentListItem store)
        json items next ctx

let sensorsHealthHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        let items = store.Sensors |> List.map (Astra.Server.Mappers.sensorHealth store)
        json items next ctx

let assistantEntityHandler (store: AstraStore) (provider: Astra.Server.Assistant.IAnalysisProvider) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            match store.TryGetEntity(EntityId g) with
            | Some e ->
                let bundle = Astra.Server.Assistant.bundleFor store e
                json (provider.Summarize bundle) next ctx
            | None -> (setStatusCode 404 >=> json { Error = "not_found"; Detail = "entity not found" }) next ctx
        | _ -> badRequest "invalid entity id" next ctx

// ------------------------------------------------------------------ ingestion
let private requireSensorToken (token: string) : HttpHandler =
    fun next ctx ->
        match ctx.TryGetRequestHeader "X-Astra-Sensor-Token" with
        | Some t when t = token -> next ctx
        | _ -> (setStatusCode 401 >=> json { Error = "unauthorized"; Detail = "invalid sensor token" }) next ctx

let ingestEventsHandler (pipeline: IngestionPipeline) (token: string) : HttpHandler =
    requireSensorToken token >=>
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<IngestBatchRequest> body
                let accepted, errors =
                    match Astra.Server.Ingestion.Mapping.fromDtoBatch req with
                    | Ok events ->
                        events |> List.iter pipeline.Submit
                        events.Length, []
                    | Error e -> 0, [ e ]
                let resp = { Accepted = accepted; Rejected = req.Events.Length - accepted; Errors = errors }
                return! json resp next ctx
            with ex ->
                return! badRequest (sprintf "invalid ingest batch: %s" ex.Message) next ctx
        }

let heartbeatHandler (store: AstraStore) (token: string) : HttpHandler =
    requireSensorToken token >=>
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let hb = Astra.Server.Json.deserialize<HeartbeatRequest> body
                match Guid.TryParse hb.SensorId with
                | true, g ->
                    let sid = SensorId g
                    let sample =
                        { SensorId = sid; SampledAt = DateTimeOffset.UtcNow
                          CpuPercent = hb.CpuPercent; MemoryPercent = hb.MemoryPercent
                          DiskPercent = hb.DiskPercent; InterfaceUp = hb.InterfaceUp
                          PacketDropPercent = hb.PacketDropPercent; EventsPerSecond = hb.EventsPerSecond
                          BufferedEvents = hb.BufferedEvents; ZeekRunning = hb.ZeekRunning
                          SuricataRunning = hb.SuricataRunning; Errors = hb.Errors }
                    store.RecordHealth sample
                    match store.TryGetSensor sid with
                    | Some s -> store.UpsertSensor { s with LastHeartbeat = Some DateTimeOffset.UtcNow; Status = SensorStatus.Online; Version = hb.Version }
                    | None ->
                        // Auto-register on first heartbeat (streamlined enrollment; full
                        // secure enrollment flow lands in Phase 2).
                        store.UpsertSensor
                            { SensorId = sid
                              Name = hb.SensorName
                              Description = "Auto-registered on first heartbeat"
                              Zone = "unassigned"
                              Location = ""
                              GroupName = "default"
                              Mode = SensorMode.LiveCapture
                              Capabilities = { ZeekEnabled = hb.ZeekRunning; SuricataEnabled = hb.SuricataRunning; FlowEnabled = true; PcapReplayEnabled = false }
                              Version = hb.Version
                              Status = SensorStatus.Online
                              EnrolledAt = DateTimeOffset.UtcNow
                              LastHeartbeat = Some DateTimeOffset.UtcNow
                              CaptureInterfaces = []
                              Tags = [ "auto-registered" ] }
                    return! json { Acknowledged = true; ConfigVersion = 1 } next ctx
                | _ -> return! badRequest "invalid sensor id" next ctx
            with ex ->
                return! badRequest (sprintf "invalid heartbeat: %s" ex.Message) next ctx
        }

// ------------------------------------------------------------------ routing
let webApp (store: AstraStore) (pipeline: IngestionPipeline) (provider: Astra.Server.Assistant.IAnalysisProvider) (token: string) : HttpHandler =
    choose [
        GET >=> choose [
            route Routes.health >=> healthHandler
            route Routes.dashboardSummary >=> dashboardHandler store
            route Routes.entityQueue >=> entityQueueHandler store
            routef "/api/assistant/entity/%s" (assistantEntityHandler store provider)
            routef "/api/entities/%s" (entityDetailHandler store)
            route Routes.detections >=> detectionsHandler store
            routef "/api/detections/%s" (detectionDetailHandler store)
            route Routes.incidents >=> incidentsHandler store
            route Routes.sensorsHealth >=> sensorsHealthHandler store
        ]
        POST >=> choose [
            route Routes.ingestEvents >=> ingestEventsHandler pipeline token
            route Routes.ingestHeartbeat >=> heartbeatHandler store token
        ]
        setStatusCode 404 >=> json { Error = "not_found"; Detail = "no such route" }
    ]
