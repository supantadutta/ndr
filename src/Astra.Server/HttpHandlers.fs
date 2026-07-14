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

// ---------------------------------------------------- detection engineering
let rulesHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        let items = store.RuleConfigs |> List.sortBy (fun d -> let (RuleId r) = d.RuleId in r) |> List.map (Astra.Server.Mappers.ruleDto store)
        json items next ctx

let updateRuleHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        task {
            match store.TryGetRuleConfig(RuleId id) with
            | None -> return! (setStatusCode 404 >=> json { Error = "not_found"; Detail = "rule not found" }) next ctx
            | Some def ->
                try
                    let! body = ctx.ReadBodyFromRequestAsync()
                    let req = Astra.Server.Json.deserialize<RuleUpdateRequest> body
                    let newThresholds =
                        req.Thresholds |> List.fold (fun (m: Map<string, float>) t -> Map.add t.Key t.Value m) def.Thresholds
                    let updated =
                        { def with
                            Enabled = defaultArg req.Enabled def.Enabled
                            Thresholds = newThresholds
                            Version = def.Version + 1
                            UpdatedAt = DateTimeOffset.UtcNow }
                    store.UpsertRuleConfig updated
                    store.Audit
                        { At = DateTimeOffset.UtcNow; Actor = "analyst"; ActorKind = "user"
                          Action = (if req.Enabled = Some false then "rule.disable" elif req.Enabled = Some true then "rule.enable" else "rule.tune")
                          SubjectKind = "rule"; SubjectId = id; Details = Map.empty }
                    return! json (Astra.Server.Mappers.ruleDto store updated) next ctx
                with ex -> return! badRequest (sprintf "invalid rule update: %s" ex.Message) next ctx
        }

// ------------------------------------------------------------------- triage
let private triageStateOf = function
    | "close_benign" -> Some (TriageState.ClosedBenign, "triage.close_benign")
    | "close_remediated" -> Some (TriageState.ClosedRemediated, "triage.close_remediated")
    | "expected" -> Some (TriageState.ExpectedBehavior, "triage.mark_expected")
    | "escalate" -> Some (TriageState.Escalated, "triage.escalate")
    | "in_progress" -> Some (TriageState.InProgress, "triage.in_progress")
    | "reopen" -> Some (TriageState.Untriaged, "triage.reopen")
    | _ -> None

let triageDetectionHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        task {
            match Guid.TryParse id with
            | false, _ -> return! badRequest "invalid detection id" next ctx
            | true, g ->
                match store.TryGetDetection(DetectionId g) with
                | None -> return! (setStatusCode 404 >=> json { Error = "not_found"; Detail = "detection not found" }) next ctx
                | Some d ->
                    try
                        let! body = ctx.ReadBodyFromRequestAsync()
                        let req = Astra.Server.Json.deserialize<TriageRequest> body
                        match triageStateOf req.Action with
                        | None -> return! badRequest (sprintf "unknown triage action: %s" req.Action) next ctx
                        | Some (state, auditAction) ->
                            let closed = (state = TriageState.ClosedBenign || state = TriageState.ClosedRemediated)
                            let updated =
                                { d with
                                    TriageState = state
                                    Status = (if closed then "closed" else "open")
                                    AssignedOwner = (match req.Owner with Some o -> Some o | None -> d.AssignedOwner)
                                    UpdatedAt = DateTimeOffset.UtcNow }
                            store.UpdateDetection updated
                            store.Audit
                                { At = DateTimeOffset.UtcNow; Actor = req.Actor; ActorKind = "user"
                                  Action = auditAction; SubjectKind = "detection"; SubjectId = id
                                  Details = (match req.Note with Some n -> Map.ofList [ "note", n ] | None -> Map.empty) }
                            // rescore the affected entity so suppression takes effect immediately
                            match store.TryGetEntity d.AffectedEntity with
                            | Some e -> store.SetScoreBreakdown(Astra.Server.ScoringEngine.computeBreakdown store DateTimeOffset.UtcNow e)
                                        store.UpsertEntity { e with Scores = (store.TryGetScoreBreakdown e.EntityId |> Option.map (fun b -> b.Scores) |> Option.defaultValue e.Scores) }
                            | None -> ()
                            return! json (Astra.Server.Mappers.detectionDetail store updated) next ctx
                    with ex -> return! badRequest (sprintf "invalid triage request: %s" ex.Message) next ctx
        }

// ------------------------------------------------------- filters & allowlists
let triageFiltersHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.TriageFilters |> List.map Astra.Server.Mappers.triageFilterDto) next ctx

let createTriageFilterHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<CreateTriageFilterRequest> body
                let action =
                    match req.Action with
                    | "hide" -> TriageAction.Hide | "tag" -> TriageAction.Tag | _ -> TriageAction.SuppressScoring
                let filter =
                    { FilterId = Guid.NewGuid(); Name = req.Name; Description = req.Description
                      Conditions = req.Conditions; Action = action; CreatedBy = req.Actor
                      CreatedAt = DateTimeOffset.UtcNow; Enabled = true }
                store.UpsertTriageFilter filter
                store.Audit
                    { At = DateTimeOffset.UtcNow; Actor = req.Actor; ActorKind = "user"
                      Action = "filter.create"; SubjectKind = "filter"; SubjectId = string filter.FilterId; Details = Map.empty }
                return! json (Astra.Server.Mappers.triageFilterDto filter) next ctx
            with ex -> return! badRequest (sprintf "invalid filter: %s" ex.Message) next ctx
        }

let allowlistsHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.Allowlists |> List.map Astra.Server.Mappers.allowlistDto) next ctx

let createAllowlistHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<CreateAllowlistRequest> body
                let kind =
                    match req.Kind with
                    | "ip" -> AllowlistKind.Ip | "cidr" -> AllowlistKind.Cidr | "domain" -> AllowlistKind.Domain
                    | "account" -> AllowlistKind.Account | "port" -> AllowlistKind.Port
                    | "protocol" -> AllowlistKind.Protocol | "sensor" -> AllowlistKind.Sensor | k -> AllowlistKind.Other k
                let entry =
                    { AllowlistId = Guid.NewGuid(); Name = req.Name; Kind = kind; Value = req.Value
                      Reason = req.Reason; CreatedBy = req.Actor; CreatedAt = DateTimeOffset.UtcNow
                      ExpiresAt = None; Enabled = true }
                store.UpsertAllowlist entry
                store.Audit
                    { At = DateTimeOffset.UtcNow; Actor = req.Actor; ActorKind = "user"
                      Action = "allowlist.create"; SubjectKind = "allowlist"; SubjectId = string entry.AllowlistId; Details = Map.empty }
                return! json (Astra.Server.Mappers.allowlistDto entry) next ctx
            with ex -> return! badRequest (sprintf "invalid allowlist: %s" ex.Message) next ctx
        }

let auditHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.AuditLog |> List.truncate 200 |> List.map Astra.Server.Mappers.auditDto) next ctx

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

// --------------------------------------------------------------- graph (P4)
let private graphWindow (store: AstraStore) = store.RecentEvents(TimeSpan.FromHours 6.0)

let graphEntityHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            let graph = Astra.Server.Graph.entityGraph store (graphWindow store) (EntityId g)
            json (Astra.Server.Mappers.investigationGraphDto graph) next ctx
        | _ -> badRequest "invalid entity id" next ctx

let graphIncidentHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            let graph = Astra.Server.Graph.incidentGraph store (graphWindow store) (IncidentId g)
            json (Astra.Server.Mappers.investigationGraphDto graph) next ctx
        | _ -> badRequest "invalid incident id" next ctx

// ---------------------------------------------------------------- hunt (P4)
let huntTemplatesHandler : HttpHandler =
    fun next ctx ->
        json (Astra.Server.Hunt.templates |> List.map Astra.Server.Mappers.huntTemplateDto) next ctx

let huntSearchHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let dto = Astra.Server.Json.deserialize<HuntQueryDto> body
                let result = Astra.Server.Hunt.run store (Astra.Server.Mappers.huntQueryOfDto dto)
                return! json (Astra.Server.Mappers.huntResultDto result) next ctx
            with ex ->
                return! badRequest (sprintf "invalid hunt query: %s" ex.Message) next ctx
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
            route Routes.rules >=> rulesHandler store
            route Routes.triageFilters >=> triageFiltersHandler store
            route Routes.allowlists >=> allowlistsHandler store
            route Routes.auditLog >=> auditHandler store
            route Routes.huntTemplates >=> huntTemplatesHandler
            routef "/api/graph/entity/%s" (graphEntityHandler store)
            routef "/api/graph/incident/%s" (graphIncidentHandler store)
        ]
        POST >=> choose [
            route Routes.ingestEvents >=> ingestEventsHandler pipeline token
            route Routes.ingestHeartbeat >=> heartbeatHandler store token
            routef "/api/detections/%s/triage" (triageDetectionHandler store)
            routef "/api/rules/%s" (updateRuleHandler store)
            route Routes.triageFilters >=> createTriageFilterHandler store
            route Routes.allowlists >=> createAllowlistHandler store
            route Routes.huntSearch >=> huntSearchHandler store
        ]
        setStatusCode 404 >=> json { Error = "not_found"; Detail = "no such route" }
    ]
