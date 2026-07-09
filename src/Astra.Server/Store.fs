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

    /// Deduplication key: one open detection per (rule, affected entity).
    member _.HasOpenDetection(ruleId: RuleId, entity: EntityId) =
        detections.Values
        |> Seq.exists (fun d -> d.RuleId = ruleId && d.AffectedEntity = entity && d.Status = "open")

    // ---------------------------------------------------------------- incidents
    member _.AddIncident(i: Incident) = incidents.[i.IncidentId] <- i
    member _.Incidents = incidents.Values |> Seq.toList
    member _.TryGetIncident(id) = match incidents.TryGetValue id with | true, i -> Some i | _ -> None

    // ------------------------------------------------------------------ scoring
    member _.SetScoreBreakdown(b: ScoreBreakdown) = scoreBreakdowns.[b.EntityId] <- b
    member _.TryGetScoreBreakdown(id) =
        match scoreBreakdowns.TryGetValue id with | true, b -> Some b | _ -> None
