module Astra.Server.Config

open System

type ServerConfig =
    { /// Postgres connection string; empty disables persistence (in-memory mode).
      PostgresConnectionString: string
      /// Directory containing ordered .sql migration files.
      MigrationsPath: string
      /// Shared secret sensors present in the X-Astra-Sensor-Token header.
      SensorApiToken: string
      /// Seed demo data at startup when the store is empty.
      SeedDemoData: bool
      /// Allowed CORS origins for the analyst console (dev mode).
      CorsOrigins: string list
      /// Detection engine sliding-window size.
      DetectionWindow: TimeSpan
      /// How often the ingestion worker flushes and runs detections.
      DetectionInterval: TimeSpan }

let private env name fallback =
    match Environment.GetEnvironmentVariable name with
    | null | "" -> fallback
    | v -> v

let private envBool name fallback =
    match Environment.GetEnvironmentVariable name with
    | null | "" -> fallback
    | v -> v.Equals("true", StringComparison.OrdinalIgnoreCase) || v = "1"

let load () =
    { PostgresConnectionString = env "ASTRA_POSTGRES" ""
      MigrationsPath = env "ASTRA_MIGRATIONS_PATH" (IO.Path.Combine(AppContext.BaseDirectory, "migrations"))
      SensorApiToken = env "ASTRA_SENSOR_TOKEN" "dev-sensor-token-change-me"
      SeedDemoData = envBool "ASTRA_SEED_DEMO" true
      CorsOrigins =
        (env "ASTRA_CORS_ORIGINS" "http://localhost:5173").Split(',')
        |> Array.map (fun s -> s.Trim())
        |> Array.filter (fun s -> s <> "")
        |> Array.toList
      DetectionWindow = TimeSpan.FromMinutes(float (env "ASTRA_DETECTION_WINDOW_MIN" "30" |> int))
      DetectionInterval = TimeSpan.FromSeconds(float (env "ASTRA_DETECTION_INTERVAL_SEC" "15" |> int)) }
