module Astra.Server.Db

open System
open System.IO
open Npgsql
open Microsoft.Extensions.Logging

/// Minimal forward-only migration runner. Applies db/migrations/*.sql in
/// filename order and records them in schema_migrations. Persistence of live
/// objects lands in Phase 2 (Postgres relational state + ClickHouse telemetry);
/// Phase 1 uses the migrations to establish the authoritative schema.

let private ensureMigrationsTable (conn: NpgsqlConnection) =
    use cmd = new NpgsqlCommand(
        "CREATE TABLE IF NOT EXISTS schema_migrations (\n" +
        "  version text PRIMARY KEY,\n" +
        "  applied_at timestamptz NOT NULL DEFAULT now())", conn)
    cmd.ExecuteNonQuery() |> ignore

let private appliedVersions (conn: NpgsqlConnection) =
    use cmd = new NpgsqlCommand("SELECT version FROM schema_migrations", conn)
    use reader = cmd.ExecuteReader()
    let versions = ResizeArray<string>()
    while reader.Read() do versions.Add(reader.GetString 0)
    Set.ofSeq versions

/// Returns Ok (number of migrations applied) or Error message. Never throws.
let runMigrations (connectionString: string) (migrationsPath: string) (logger: ILogger) =
    if String.IsNullOrWhiteSpace connectionString then
        Ok 0
    else
        try
            use conn = new NpgsqlConnection(connectionString)
            conn.Open()
            ensureMigrationsTable conn
            let applied = appliedVersions conn
            let files =
                if Directory.Exists migrationsPath then
                    Directory.GetFiles(migrationsPath, "*.sql") |> Array.sort
                else [||]
            let mutable count = 0
            for file in files do
                let version = Path.GetFileNameWithoutExtension file
                if not (applied.Contains version) then
                    let sql = File.ReadAllText file
                    use tx = conn.BeginTransaction()
                    use cmd = new NpgsqlCommand(sql, conn, tx)
                    cmd.ExecuteNonQuery() |> ignore
                    use record = new NpgsqlCommand("INSERT INTO schema_migrations (version) VALUES (@v)", conn, tx)
                    record.Parameters.AddWithValue("v", version) |> ignore
                    record.ExecuteNonQuery() |> ignore
                    tx.Commit()
                    logger.LogInformation("Applied migration {Version}", version)
                    count <- count + 1
            Ok count
        with ex ->
            Error ex.Message
