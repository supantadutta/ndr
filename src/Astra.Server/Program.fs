module Astra.Server.Program

open System
open Microsoft.AspNetCore.Builder
open Microsoft.Extensions.DependencyInjection
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Giraffe
open Astra.Shared
open Astra.Server.Store
open Astra.Server.Classification
open Astra.Server.Ingestion

[<EntryPoint>]
let main args =
    let config = Config.load ()
    let builder = WebApplication.CreateBuilder(args)

    builder.Logging.ClearProviders().AddSimpleConsole(fun o ->
        o.SingleLine <- true
        o.TimestampFormat <- "HH:mm:ss ") |> ignore

    let store = AstraStore()
    let classifier = Classifier(CoverageConfig.empty)

    builder.Services
        .AddGiraffe()
        .AddSingleton(store)
        .AddSingleton(classifier)
        .AddSingleton(config)
        .AddSingleton<Astra.Server.Telemetry.ITelemetrySink>(fun sp ->
            let logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Astra.Telemetry")
            Astra.Server.Telemetry.create config logger)
        .AddSingleton<IngestionPipeline>(fun sp ->
            let logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Astra.Ingestion")
            let sink = sp.GetRequiredService<Astra.Server.Telemetry.ITelemetrySink>()
            IngestionPipeline(store, classifier, config, sink, logger))
        .AddHostedService<IngestionWorker>(fun sp ->
            new IngestionWorker(sp.GetRequiredService<IngestionPipeline>(), config,
                                sp.GetRequiredService<ILogger<IngestionWorker>>()))
        .AddCors(fun o ->
            o.AddPolicy("console", fun p ->
                p.WithOrigins(config.CorsOrigins |> List.toArray)
                 .AllowAnyHeader()
                 .AllowAnyMethod() |> ignore)) |> ignore

    let app = builder.Build()
    let logger = app.Services.GetRequiredService<ILogger<obj>>()

    // ---- database migrations (best-effort: server stays up without a DB) ----
    match Db.runMigrations config.PostgresConnectionString config.MigrationsPath logger with
    | Ok 0 when String.IsNullOrWhiteSpace config.PostgresConnectionString ->
        logger.LogWarning("ASTRA_POSTGRES not set - running with in-memory store only")
    | Ok n -> logger.LogInformation("Database ready ({Count} new migrations applied)", n)
    | Error msg -> logger.LogWarning("Database unavailable ({Message}) - continuing in-memory", msg)

    // ---- telemetry persistence (best-effort: bootstrap schema/index) ----
    let telemetrySink = app.Services.GetRequiredService<Astra.Server.Telemetry.ITelemetrySink>()
    telemetrySink.Bootstrap ()
    let ts = telemetrySink.Status
    if ts.Backend = "in-memory" then
        logger.LogInformation("Telemetry: in-memory only (set ASTRA_CLICKHOUSE_URL or ASTRA_OPENSEARCH_URL for durable persistence)")
    else
        logger.LogInformation("Telemetry backend: {Backend} ({Endpoint}), healthy={Healthy}", ts.Backend, ts.Endpoint, ts.Healthy)

    // ---- demo seed ----
    let pipeline = app.Services.GetRequiredService<IngestionPipeline>()
    if config.SeedDemoData && store.EventCount = 0L then
        logger.LogInformation("Seeding demo environment (ASTRA_SEED_DEMO=true)")
        let sensors = SeedData.seedSensors ()
        sensors |> List.iter store.UpsertSensor
        SeedData.seedHealth sensors |> List.iter store.RecordHealth
        SeedData.seedIndicators () |> List.iter store.UpsertIndicator
        SeedData.seedConnectors () |> List.iter store.UpsertConnector
        let events = SeedData.generateEvents sensors
        events |> List.iter pipeline.Submit
        // run one synchronous analysis pass so the dashboard is populated immediately
        pipeline.DrainOnce(Threading.CancellationToken.None) |> ignore
        let detections, incidents = pipeline.RunAnalysisCycle()
        logger.LogInformation("Seed complete: {Events} events, {Detections} detections, {Incidents} incidents",
                              events.Length, detections.Length, incidents.Length)

    let analysisProvider = Assistant.createProvider ()
    match Assistant.loadLlmConfig () with
    | Some cfg -> logger.LogInformation("LLM analysis endpoint configured ({Model}); provider stays evidence-bound", cfg.Model)
    | None -> logger.LogInformation("AI assistant using deterministic evidence-bound provider (set ASTRA_LLM_ENDPOINT to attach a model)")

    // ---- authentication (RBAC; pass-through when disabled) ----
    let auth = Astra.Server.Auth.AuthService(store, config)
    if config.AuthEnabled then
        match auth.EnsureAdmin() with
        | Some username -> logger.LogInformation("Auth enabled - bootstrap admin '{User}' created (set ASTRA_ADMIN_PASSWORD)", username)
        | None -> logger.LogInformation("Auth enabled")
        if config.AdminPassword = "changeme-admin" then
            logger.LogWarning("ASTRA_ADMIN_PASSWORD is the default - change it before exposing this server")
    else
        logger.LogWarning("Auth disabled (dev/demo mode) - set ASTRA_AUTH_ENABLED=true for production")

    // ---- response connector delivery (live when a connector leaves simulation) ----
    let dispatcher =
        Astra.Server.Connectors.RealConnectorDispatcher(
            app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Astra.Connectors"))
        :> Astra.Server.Connectors.IConnectorDispatcher

    app.UseCors("console") |> ignore
    app.UseGiraffe(HttpHandlers.webApp store pipeline analysisProvider auth dispatcher config.SensorApiToken)

    logger.LogInformation("Astra NDR central brain listening")
    app.Run()
    0
