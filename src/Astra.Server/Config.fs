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
      DetectionInterval: TimeSpan
      // ---- telemetry persistence (Phase 6) ----
      /// ClickHouse HTTP endpoint (e.g. http://clickhouse:8123). Empty disables it.
      ClickHouseUrl: string
      ClickHouseDatabase: string
      ClickHouseTable: string
      ClickHouseUser: string
      ClickHousePassword: string
      /// OpenSearch/Elasticsearch base URL (e.g. http://opensearch:9200). Empty disables it.
      OpenSearchUrl: string
      OpenSearchIndex: string
      OpenSearchUser: string
      OpenSearchPassword: string
      // ---- authentication (Phase 6) ----
      /// When true, API routes require a session token or API key (RBAC enforced).
      AuthEnabled: bool
      /// Bootstrap admin account, created at startup when auth is enabled.
      AdminUsername: string
      AdminPassword: string
      /// Session lifetime.
      SessionTtl: TimeSpan }

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
      DetectionInterval = TimeSpan.FromSeconds(float (env "ASTRA_DETECTION_INTERVAL_SEC" "15" |> int))
      ClickHouseUrl = env "ASTRA_CLICKHOUSE_URL" ""
      ClickHouseDatabase = env "ASTRA_CLICKHOUSE_DB" "astra"
      ClickHouseTable = env "ASTRA_CLICKHOUSE_TABLE" "events"
      ClickHouseUser = env "ASTRA_CLICKHOUSE_USER" ""
      ClickHousePassword = env "ASTRA_CLICKHOUSE_PASSWORD" ""
      OpenSearchUrl = env "ASTRA_OPENSEARCH_URL" ""
      OpenSearchIndex = env "ASTRA_OPENSEARCH_INDEX" "astra-events"
      OpenSearchUser = env "ASTRA_OPENSEARCH_USER" ""
      OpenSearchPassword = env "ASTRA_OPENSEARCH_PASSWORD" ""
      AuthEnabled = envBool "ASTRA_AUTH_ENABLED" false
      AdminUsername = env "ASTRA_ADMIN_USER" "admin"
      AdminPassword = env "ASTRA_ADMIN_PASSWORD" "changeme-admin"
      SessionTtl = TimeSpan.FromHours(float (env "ASTRA_SESSION_TTL_HOURS" "12" |> int)) }
