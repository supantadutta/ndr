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
        .AddSingleton<IngestionPipeline>(fun sp ->
            let logger = sp.GetRequiredService<ILoggerFactory>().CreateLogger("Astra.Ingestion")
            IngestionPipeline(store, classifier, config, logger))
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

    // ---- demo seed ----
    let pipeline = app.Services.GetRequiredService<IngestionPipeline>()
    if config.SeedDemoData && store.EventCount = 0L then
        logger.LogInformation("Seeding demo environment (ASTRA_SEED_DEMO=true)")
        let sensors = SeedData.seedSensors ()
        sensors |> List.iter store.UpsertSensor
        SeedData.seedHealth sensors |> List.iter store.RecordHealth
        let events = SeedData.generateEvents sensors
        events |> List.iter pipeline.Submit
        // run one synchronous analysis pass so the dashboard is populated immediately
        pipeline.DrainOnce(Threading.CancellationToken.None) |> ignore
        let detections, incidents = pipeline.RunAnalysisCycle()
        logger.LogInformation("Seed complete: {Events} events, {Detections} detections, {Incidents} incidents",
                              events.Length, detections.Length, incidents.Length)

    app.UseCors("console") |> ignore
    app.UseGiraffe(HttpHandlers.webApp store pipeline config.SensorApiToken)

    logger.LogInformation("Astra NDR central brain listening")
    app.Run()
    0
