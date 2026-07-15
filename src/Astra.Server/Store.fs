module Astra.Server.Store

open System
open System.Collections.Concurrent
open Astra.Shared

/// Phase-1 store: thread-safe in-memory state with an entity-resolution layer.
/// The Postgres writer (Db.fs) persists the same objects best-effort; the
/// ClickHouse/OpenSearch telemetry tier arrives in Phase 2. All reads used by
/// the API go through this store so the console works with or without a DB.

type AstraStore() =
    let sensors = ConcurrentDictionary<SensorId, Sensor>()
    let sensorHealth = ConcurrentDictionary<SensorId, SensorHealthSample>()
    let events = ConcurrentQueue<NormalizedEvent>()
    let mutable eventCount = 0L
    let entities = ConcurrentDictionary<EntityId, EntityProfile>()
    let entityIndex = ConcurrentDictionary<string, EntityId>()   // canonical key -> id
    let detections = ConcurrentDictionary<DetectionId, Detection>()
    let incidents = ConcurrentDictionary<IncidentId, Incident>()
    let scoreBreakdowns = ConcurrentDictionary<EntityId, ScoreBreakdown>()
    // Phase 3: tunable rule config, triage filters/allowlists, audit, baselines.
    let ruleConfig = ConcurrentDictionary<RuleId, DetectionRuleDef>()
    let triageFilters = ConcurrentDictionary<Guid, TriageFilter>()
    let allowlists = ConcurrentDictionary<Guid, AllowlistEntry>()
    let auditLog = ConcurrentQueue<AuditEntry>()
    let baselineState = ConcurrentDictionary<string, Baselines.EwmaState>()   // "scope|metric" -> state
    // Phase 5: threat intelligence + response.
    let indicators = ConcurrentDictionary<string, ThreatIndicator>()   // "type:value" -> indicator
    let intelMatches = ConcurrentQueue<ThreatIntelMatch>()
    let responseActions = ConcurrentDictionary<Guid, ResponseAction>()
    let connectors = ConcurrentDictionary<string, ResponseConnector>()
    let maxEventsInMemory = 200_000

    // ------------------------------------------------------------------ sensors
    member _.UpsertSensor(s: Sensor) = sensors.[s.SensorId] <- s
    member _.TryGetSensor(id) = match sensors.TryGetValue id with | true, s -> Some s | _ -> None
    member _.Sensors = sensors.Values |> Seq.toList
    member _.RecordHealth(sample: SensorHealthSample) = sensorHealth.[sample.SensorId] <- sample
    member _.TryGetHealth(id) = match sensorHealth.TryGetValue id with | true, h -> Some h | _ -> None

    // ------------------------------------------------------------------- events
    member _.AddEvent(e: NormalizedEvent) =
        events.Enqueue e
        Threading.Interlocked.Increment(&eventCount) |> ignore
        // bound memory: drop oldest beyond the cap
        while events.Count > maxEventsInMemory do
            events.TryDequeue() |> ignore

    member _.RecentEvents(window: TimeSpan) =
        let cutoff = DateTimeOffset.UtcNow - window
        events |> Seq.filter (fun e -> e.Timestamp >= cutoff) |> Seq.toList

    member _.AllEvents = events |> Seq.toList
    member _.EventCount = Threading.Interlocked.Read(&eventCount)

    // ----------------------------------------------------------------- entities
    member _.UpsertEntity(p: EntityProfile) =
        entities.[p.EntityId] <- p
        entityIndex.[sprintf "%s:%s" (EntityType.label p.EntityType) (p.CanonicalName.ToLowerInvariant())] <- p.EntityId

    member _.TryGetEntity(id) = match entities.TryGetValue id with | true, e -> Some e | _ -> None
    member _.Entities = entities.Values |> Seq.toList

    /// Entity resolution: find-or-create by (type, canonical name).
    member this.ResolveEntity(entityType: EntityType, canonicalName: string, displayName: string, now: DateTimeOffset) =
        let key = sprintf "%s:%s" (EntityType.label entityType) (canonicalName.ToLowerInvariant())
        match entityIndex.TryGetValue key with
        | true, id ->
            match entities.TryGetValue id with
            | true, existing ->
                let updated = { existing with LastSeen = max existing.LastSeen now }
                entities.[id] <- updated
                updated
            | _ -> this.CreateEntity(entityType, canonicalName, displayName, now)
        | _ -> this.CreateEntity(entityType, canonicalName, displayName, now)

    member private this.CreateEntity(entityType, canonicalName: string, displayName, now) =
        let profile =
            { EntityId = EntityId(Guid.NewGuid())
              EntityType = entityType
              DisplayName = displayName
              CanonicalName = canonicalName
              KnownAliases = []
              FirstSeen = now
              LastSeen = now
              LastObservedSensor = None
              IdentityConfidence = 60
              Criticality = Criticality.Normal
              BusinessUnit = None
              Owner = None
              Location = None
              Tags = []
              GroupMemberships = []
              IdentitySources = [ "network_observation" ]
              Behavior =
                { NormalProtocols = []; NormalPorts = []; NormalPeers = []
                  NormalLoginSources = []; NormalLoginHours = None
                  NormalExternalDestinations = []; NormalDnsQueryRatePerHour = None
                  NormalByteVolumePerDay = None }
              Scores = { Risk = 0; Urgency = 0; Threat = 0; Certainty = 0 }
              RelatedDetectionCount = 0
              RelatedIncidentCount = 0
              AnalystNotes = []
              TriageState = TriageState.Untriaged }
        this.UpsertEntity profile
        profile

    // --------------------------------------------------------------- detections
    member _.AddDetection(d: Detection) = detections.[d.DetectionId] <- d
    member _.TryGetDetection(id) = match detections.TryGetValue id with | true, d -> Some d | _ -> None
    member _.Detections = detections.Values |> Seq.toList

    /// Deduplication: don't re-raise a (rule, entity) finding that is already
    /// open OR that an analyst has already dismissed/handled. Without the second
    /// clause, closing a detection as benign would let the next analysis cycle
    /// immediately re-raise it. A `reopen` sets status=open + Untriaged, which is
    /// covered by the open check so reopened findings behave normally.
    member _.HasOpenDetection(ruleId: RuleId, entity: EntityId) =
        detections.Values
        |> Seq.exists (fun d ->
            d.RuleId = ruleId && d.AffectedEntity = entity
            && (d.Status = "open"
                || (match d.TriageState with
                    | TriageState.ClosedBenign | TriageState.ClosedRemediated | TriageState.ExpectedBehavior -> true
                    | _ -> false)))

    // ---------------------------------------------------------------- incidents
    member _.AddIncident(i: Incident) = incidents.[i.IncidentId] <- i
    member _.Incidents = incidents.Values |> Seq.toList
    member _.TryGetIncident(id) = match incidents.TryGetValue id with | true, i -> Some i | _ -> None

    /// Replace a detection (e.g. after a triage state change).
    member _.UpdateDetection(d: Detection) = detections.[d.DetectionId] <- d

    // ------------------------------------------------------------------ scoring
    member _.SetScoreBreakdown(b: ScoreBreakdown) = scoreBreakdowns.[b.EntityId] <- b
    member _.TryGetScoreBreakdown(id) =
        match scoreBreakdowns.TryGetValue id with | true, b -> Some b | _ -> None

    // -------------------------------------------------------------- rule config
    /// Tunable rule config overlays the engine's built-in defaults. Seeded from
    /// the engine at startup, then mutated by detection-engineering actions.
    member _.SeedRuleConfig(defs: DetectionRuleDef list) =
        for d in defs do ruleConfig.TryAdd(d.RuleId, d) |> ignore
    member _.RuleConfigs = ruleConfig.Values |> Seq.toList
    member _.TryGetRuleConfig(id) = match ruleConfig.TryGetValue id with | true, d -> Some d | _ -> None
    member _.UpsertRuleConfig(d: DetectionRuleDef) = ruleConfig.[d.RuleId] <- d
    member _.IsRuleEnabled(id: RuleId) =
        match ruleConfig.TryGetValue id with | true, d -> d.Enabled | _ -> true
    member _.RuleThreshold(id: RuleId, key: string, fallback: float) =
        match ruleConfig.TryGetValue id with
        | true, d -> d.Thresholds |> Map.tryFind key |> Option.defaultValue fallback
        | _ -> fallback

    // ------------------------------------------------------------ triage filters
    member _.UpsertTriageFilter(f: TriageFilter) = triageFilters.[f.FilterId] <- f
    member _.TriageFilters = triageFilters.Values |> Seq.toList
    member _.RemoveTriageFilter(id: Guid) = triageFilters.TryRemove id |> ignore
    /// The first enabled filter matching a detection's tuning fields, if any.
    member _.MatchingFilter(tuningFields: Map<string, string>) =
        triageFilters.Values |> Seq.tryFind (fun f -> TriageFilter.matches f tuningFields)

    // ---------------------------------------------------------------- allowlists
    member _.UpsertAllowlist(a: AllowlistEntry) = allowlists.[a.AllowlistId] <- a
    member _.Allowlists = allowlists.Values |> Seq.toList
    member _.RemoveAllowlist(id: Guid) = allowlists.TryRemove id |> ignore

    // -------------------------------------------------------------------- audit
    member _.Audit(entry: AuditEntry) = auditLog.Enqueue entry
    member _.AuditLog = auditLog |> Seq.toList |> List.sortByDescending (fun e -> e.At)

    // ----------------------------------------------------------------- baselines
    member _.GetBaseline(key: string, alpha: float) =
        match baselineState.TryGetValue key with
        | true, s -> s
        | _ -> Baselines.Ewma.create alpha
    member _.SetBaseline(key: string, s: Baselines.EwmaState) = baselineState.[key] <- s

    // ----------------------------------------------------------- threat intel
    member _.UpsertIndicator(i: ThreatIndicator) =
        indicators.[sprintf "%s:%s" (IndicatorType.label i.IndicatorType) (i.Indicator.ToLowerInvariant())] <- i
    member _.Indicators = indicators.Values |> Seq.toList
    member _.TryMatchIndicator(indType: IndicatorType, value: string) =
        match indicators.TryGetValue(sprintf "%s:%s" (IndicatorType.label indType) (value.ToLowerInvariant())) with
        | true, i when i.Enabled -> Some i
        | _ -> None
    member _.Feeds =
        indicators.Values
        |> Seq.groupBy (fun i -> i.FeedName)
        |> Seq.map (fun (name, items) ->
            let items = Seq.toList items
            { FeedId = Guid.Empty; Name = name; Kind = FeedKind.Manual
              IndicatorCount = items.Length
              LastUpdate = (items |> List.map (fun i -> i.LastSeen) |> function [] -> None | xs -> Some (List.max xs))
              Status = "active" })
        |> Seq.toList
    member _.RecordIntelMatch(m: ThreatIntelMatch) = intelMatches.Enqueue m
    member _.IntelMatches = intelMatches |> Seq.toList |> List.sortByDescending (fun m -> m.MatchedAt)

    // -------------------------------------------------------------- response
    member _.UpsertResponseAction(a: ResponseAction) = responseActions.[a.ActionId] <- a
    member _.ResponseActions = responseActions.Values |> Seq.toList |> List.sortByDescending (fun a -> a.CreatedAt)
    member _.TryGetResponseAction(id: Guid) = match responseActions.TryGetValue id with | true, a -> Some a | _ -> None
    member _.UpsertConnector(c: ResponseConnector) = connectors.[c.ConnectorName] <- c
    member _.Connectors = connectors.Values |> Seq.toList
