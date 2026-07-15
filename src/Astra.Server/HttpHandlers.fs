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

// -------------------------------------------------------- threat intel (P5)
let tiIndicatorsHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.Indicators |> List.map Astra.Server.Mappers.indicatorDto) next ctx

let tiFeedsHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.Feeds |> List.map Astra.Server.Mappers.feedDto) next ctx

let tiMatchesHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.IntelMatches |> List.truncate 200 |> List.map Astra.Server.Mappers.threatMatchDto) next ctx

let tiCreateIndicatorHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<CreateIndicatorRequest> body
                let now = DateTimeOffset.UtcNow
                store.UpsertIndicator
                    { IndicatorId = Guid.NewGuid(); Indicator = req.Indicator
                      IndicatorType = IndicatorType.parse req.IndicatorType
                      FeedName = (if System.String.IsNullOrWhiteSpace req.FeedName then "analyst" else req.FeedName)
                      ActorLabel = req.Actor; ToolLabel = None; CampaignLabel = None
                      Confidence = req.Confidence; FirstSeen = now; LastSeen = now; ExpiresAt = None; Enabled = true }
                store.Audit { At = now; Actor = req.CreatedBy; ActorKind = "user"; Action = "intel.add_indicator"; SubjectKind = "indicator"; SubjectId = req.Indicator; Details = Map.empty }
                return! json (store.Indicators |> List.map Astra.Server.Mappers.indicatorDto) next ctx
            with ex -> return! badRequest (sprintf "invalid indicator: %s" ex.Message) next ctx
        }

let tiImportHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<ImportIndicatorsRequest> body
                let n = Astra.Server.ThreatIntel.importCsv store req.FeedName req.Csv
                store.Audit { At = DateTimeOffset.UtcNow; Actor = req.Actor; ActorKind = "user"; Action = "intel.import_csv"; SubjectKind = "feed"; SubjectId = req.FeedName; Details = Map.ofList [ "count", string n ] }
                return! json { Imported = n } next ctx
            with ex -> return! badRequest (sprintf "invalid import: %s" ex.Message) next ctx
        }

// ------------------------------------------------------------- response (P5)
let responseActionsHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.ResponseActions |> List.map Astra.Server.Mappers.responseActionDto) next ctx

let responseConnectorsHandler (store: AstraStore) : HttpHandler =
    fun next ctx -> json (store.Connectors |> List.map Astra.Server.Mappers.connectorDto) next ctx

let requestResponseActionHandler (store: AstraStore) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<RequestResponseActionRequest> body
                let action = Astra.Server.Response.request store (ResponseActionKind.parse req.Kind) req.Target req.Reason req.Evidence [] req.Actor
                return! json (Astra.Server.Mappers.responseActionDto action) next ctx
            with ex -> return! badRequest (sprintf "invalid response request: %s" ex.Message) next ctx
        }

let approveActionHandler (store: AstraStore) (dispatcher: Astra.Server.Connectors.IConnectorDispatcher) (id: string) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<ApproveActionRequest> body
                match Guid.TryParse id with
                | true, g ->
                    match Astra.Server.Response.approveWith (Some dispatcher) store g req.Actor with
                    | Ok a -> return! json (Astra.Server.Mappers.responseActionDto a) next ctx
                    | Error e -> return! badRequest e next ctx
                | _ -> return! badRequest "invalid action id" next ctx
            with ex -> return! badRequest (sprintf "invalid approve: %s" ex.Message) next ctx
        }

let rejectActionHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<ApproveActionRequest> body
                match Guid.TryParse id with
                | true, g ->
                    match Astra.Server.Response.reject store g req.Actor with
                    | Ok a -> return! json (Astra.Server.Mappers.responseActionDto a) next ctx
                    | Error e -> return! badRequest e next ctx
                | _ -> return! badRequest "invalid action id" next ctx
            with ex -> return! badRequest (sprintf "invalid reject: %s" ex.Message) next ctx
        }

let incidentReportHandler (store: AstraStore) (id: string) : HttpHandler =
    fun next ctx ->
        match Guid.TryParse id with
        | true, g ->
            match store.TryGetIncident(IncidentId g) with
            | Some inc ->
                ctx.SetContentType "text/plain; charset=utf-8"
                setBodyFromString (Astra.Server.Response.incidentReport store inc) next ctx
            | None -> (setStatusCode 404 >=> json { Error = "not_found"; Detail = "incident not found" }) next ctx
        | _ -> badRequest "invalid incident id" next ctx

// -------------------------------------------------- auth + RBAC (Phase 6)
/// Resolve the caller's identity from Authorization: Bearer <session-token>
/// or X-Astra-Api-Key. With auth disabled this is a pass-through, preserving
/// the open dev/demo behavior.
let requireAuth (auth: Astra.Server.Auth.AuthService) (permission: string) : HttpHandler =
    fun next ctx ->
        if not auth.AuthEnabled then next ctx
        else
            let bearer =
                match ctx.TryGetRequestHeader "Authorization" with
                | Some h when h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ->
                    auth.ContextFromToken (h.Substring 7)
                | _ -> None
            let resolved =
                match bearer with
                | Some c -> Some c
                | None ->
                    match ctx.TryGetRequestHeader "X-Astra-Api-Key" with
                    | Some k -> auth.ContextFromApiKey k
                    | None -> None
            match resolved with
            | None ->
                (setStatusCode 401 >=> json { Error = "unauthorized"; Detail = "missing or invalid credentials" }) next ctx
            | Some c when not (Astra.Server.Auth.hasPermission permission c.Permissions) ->
                (setStatusCode 403 >=> json { Error = "forbidden"; Detail = sprintf "requires permission '%s'" permission }) next ctx
            | Some c ->
                ctx.Items.["astra.auth"] <- c
                next ctx

let authStatusHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx -> json { AuthEnabled = auth.AuthEnabled } next ctx

let private authUserDto (auth: Astra.Server.Auth.AuthService) (username: string) (roleName: string) : AuthUserDto =
    { Username = username
      DisplayName = username
      Role = roleName
      Permissions = auth.Roles |> List.tryFind (fun r -> r.Name = roleName) |> Option.map (fun r -> r.Permissions) |> Option.defaultValue [] }

let loginHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<LoginRequest> body
                match auth.Login(req.Username, req.Password) with
                | Ok session ->
                    let resp =
                        { Token = session.Token
                          ExpiresAt = session.ExpiresAt.ToString("o")
                          User = { Username = session.Username; DisplayName = session.Username
                                   Role = session.RoleName; Permissions = session.Permissions } }
                    return! json resp next ctx
                | Error _ ->
                    // uniform error; do not reveal whether the user exists
                    return! (setStatusCode 401 >=> json { Error = "unauthorized"; Detail = "invalid credentials" }) next ctx
            with ex -> return! badRequest (sprintf "invalid login request: %s" ex.Message) next ctx
        }

let logoutHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        (match ctx.TryGetRequestHeader "Authorization" with
         | Some h when h.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) -> auth.Logout (h.Substring 7)
         | _ -> ())
        json {| loggedOut = true |} next ctx

let meHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        match ctx.Items.TryGetValue "astra.auth" with
        | true, (:? Astra.Server.Auth.AuthContext as c) ->
            json { Username = c.Subject; DisplayName = c.Subject; Role = c.RoleName; Permissions = c.Permissions } next ctx
        | _ ->
            // auth disabled: report the implicit dev identity
            json { Username = "dev"; DisplayName = "Development"; Role = "admin"; Permissions = [ "*" ] } next ctx

let usersHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        let items = auth.Users |> List.map (fun u -> authUserDto auth u.Username u.RoleName)
        json items next ctx

let createUserHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<CreateUserRequest> body
                match auth.CreateUser(req.Username, req.Password, req.DisplayName, req.Role, req.Actor) with
                | Ok u -> return! json (authUserDto auth u.Username u.RoleName) next ctx
                | Error e -> return! badRequest e next ctx
            with ex -> return! badRequest (sprintf "invalid user request: %s" ex.Message) next ctx
        }

let createApiKeyHandler (auth: Astra.Server.Auth.AuthService) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<CreateApiKeyRequest> body
                match auth.CreateApiKey(req.Name, req.Role, None, req.Actor) with
                | Ok (keyId, plaintext) ->
                    // the plaintext key is returned exactly once and never stored
                    return! json { KeyId = string keyId; ApiKey = plaintext; Name = req.Name; Role = req.Role } next ctx
                | Error e -> return! badRequest e next ctx
            with ex -> return! badRequest (sprintf "invalid api key request: %s" ex.Message) next ctx
        }

// ------------------------------------------------ telemetry status (Phase 6)
let telemetryStatusHandler (pipeline: IngestionPipeline) : HttpHandler =
    fun next ctx ->
        let s = pipeline.TelemetryStatus
        json { Backend = s.Backend; Endpoint = s.Endpoint; Healthy = s.Healthy
               Persisted = s.Persisted; Failed = s.Failed; LastError = s.LastError
               LastFlush = s.LastFlush |> Option.map (fun t -> t.ToString("o")) } next ctx

// ------------------------------------------- connector live-mode (Phase 6)
let setConnectorModeHandler (store: AstraStore) (name: string) : HttpHandler =
    fun next ctx ->
        task {
            try
                let! body = ctx.ReadBodyFromRequestAsync()
                let req = Astra.Server.Json.deserialize<SetConnectorModeRequest> body
                match store.Connectors |> List.tryFind (fun c -> c.ConnectorName = name) with
                | None -> return! (setStatusCode 404 >=> json { Error = "not_found"; Detail = "connector not found" }) next ctx
                | Some c ->
                    let updated = { c with SimulationMode = req.SimulationMode }
                    store.UpsertConnector updated
                    store.Audit
                        { At = DateTimeOffset.UtcNow; Actor = req.Actor; ActorKind = "user"
                          Action = (if req.SimulationMode then "connector.simulation_mode" else "connector.live_mode")
                          SubjectKind = "connector"; SubjectId = name; Details = Map.empty }
                    return! json (Astra.Server.Mappers.connectorDto updated) next ctx
            with ex -> return! badRequest (sprintf "invalid connector mode request: %s" ex.Message) next ctx
        }

// ------------------------------------------------------------------ routing
/// Route table with RBAC. Permission model:
///   read:api          all read endpoints (analyst/readonly roles)
///   triage:write      triage, rule tuning, filters, allowlists, intel writes
///   respond:request   requesting a response action
///   respond:approve   approving/rejecting an action (admin by default)
///   admin:manage      user/api-key management, connector live-mode toggle
/// Sensor ingestion keeps its own shared-token check. With auth disabled
/// (dev/demo) every guard is a pass-through.
let webApp (store: AstraStore) (pipeline: IngestionPipeline) (provider: Astra.Server.Assistant.IAnalysisProvider)
           (auth: Astra.Server.Auth.AuthService) (dispatcher: Astra.Server.Connectors.IConnectorDispatcher)
           (token: string) : HttpHandler =
    let guard perm = requireAuth auth perm
    choose [
        GET >=> choose [
            route Routes.health >=> healthHandler
            route Routes.authStatus >=> authStatusHandler auth
            route Routes.authMe >=> guard "read:api" >=> meHandler auth
            route Routes.authUsers >=> guard "admin:manage" >=> usersHandler auth
            route Routes.telemetryStatus >=> guard "read:api" >=> telemetryStatusHandler pipeline
            guard "read:api" >=> choose [
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
                route Routes.tiIndicators >=> tiIndicatorsHandler store
                route Routes.tiFeeds >=> tiFeedsHandler store
                route Routes.tiMatches >=> tiMatchesHandler store
                route Routes.responseActions >=> responseActionsHandler store
                route Routes.responseConnectors >=> responseConnectorsHandler store
                routef "/api/incidents/%s/report" (incidentReportHandler store)
            ]
        ]
        POST >=> choose [
            route Routes.authLogin >=> loginHandler auth
            route Routes.authLogout >=> logoutHandler auth
            route Routes.ingestEvents >=> ingestEventsHandler pipeline token
            route Routes.ingestHeartbeat >=> heartbeatHandler store token
            route Routes.authUsers >=> guard "admin:manage" >=> createUserHandler auth
            route Routes.authApiKeys >=> guard "admin:manage" >=> createApiKeyHandler auth
            routef "/api/response/connectors/%s/mode" (fun name -> guard "admin:manage" >=> setConnectorModeHandler store name)
            route Routes.huntSearch >=> guard "read:api" >=> huntSearchHandler store
            routef "/api/detections/%s/triage" (fun id -> guard "triage:write" >=> triageDetectionHandler store id)
            routef "/api/rules/%s" (fun id -> guard "triage:write" >=> updateRuleHandler store id)
            route Routes.triageFilters >=> guard "triage:write" >=> createTriageFilterHandler store
            route Routes.allowlists >=> guard "triage:write" >=> createAllowlistHandler store
            route Routes.tiIndicators >=> guard "triage:write" >=> tiCreateIndicatorHandler store
            route Routes.tiImport >=> guard "triage:write" >=> tiImportHandler store
            route Routes.responseActions >=> guard "respond:request" >=> requestResponseActionHandler store
            routef "/api/response/actions/%s/approve" (fun id -> guard "respond:approve" >=> approveActionHandler store dispatcher id)
            routef "/api/response/actions/%s/reject" (fun id -> guard "respond:approve" >=> rejectActionHandler store id)
        ]
        setStatusCode 404 >=> json { Error = "not_found"; Detail = "no such route" }
    ]
