module Astra.Tests.ProductionTests

open System
open Xunit
open Astra.Shared
open Astra.Server.Store
open Astra.Server.Auth

/// Phase 6: RBAC/session auth, connector selection + live dispatch, telemetry sink.

let private testConfig : Astra.Server.Config.ServerConfig =
    { PostgresConnectionString = ""
      MigrationsPath = ""
      SensorApiToken = "test-token"
      SeedDemoData = false
      CorsOrigins = []
      DetectionWindow = TimeSpan.FromMinutes 30.0
      DetectionInterval = TimeSpan.FromSeconds 15.0
      ClickHouseUrl = ""; ClickHouseDatabase = "astra"; ClickHouseTable = "events"
      ClickHouseUser = ""; ClickHousePassword = ""
      OpenSearchUrl = ""; OpenSearchIndex = "astra-events"
      OpenSearchUser = ""; OpenSearchPassword = ""
      AuthEnabled = true
      AdminUsername = "admin"; AdminPassword = "test-admin-pw"
      SessionTtl = TimeSpan.FromHours 1.0 }

// ------------------------------------------------------------------ hashing

[<Fact>]
let ``password hash verifies the original and rejects a wrong password`` () =
    let encoded = Hashing.hash "s3cret!"
    Assert.True(Hashing.verify "s3cret!" encoded)
    Assert.False(Hashing.verify "wrong" encoded)
    Assert.False(Hashing.verify "s3cret!" "garbage")

[<Fact>]
let ``hashing the same password twice produces different salts`` () =
    Assert.NotEqual<string>(Hashing.hash "pw", Hashing.hash "pw")

// -------------------------------------------------------------- permissions

[<Theory>]
[<InlineData("*", "respond:approve", true)>]
[<InlineData("read:*", "read:api", true)>]
[<InlineData("read:api", "read:api", true)>]
[<InlineData("read:*", "triage:write", false)>]
[<InlineData("respond:request", "respond:approve", false)>]
let ``permission wildcard matching`` (held: string) (required: string) (expected: bool) =
    Assert.Equal(expected, hasPermission required [ held ])

// -------------------------------------------------------------------- auth

[<Fact>]
let ``bootstrap admin can log in and gets a working session`` () =
    let auth = AuthService(AstraStore(), testConfig)
    Assert.Equal(Some "admin", auth.EnsureAdmin())
    match auth.Login("admin", "test-admin-pw") with
    | Error e -> failwithf "login failed: %s" e
    | Ok session ->
        Assert.True(session.ExpiresAt > DateTimeOffset.UtcNow)
        match auth.ContextFromToken session.Token with
        | Some ctx ->
            Assert.Equal("admin", ctx.Subject)
            Assert.True(hasPermission "respond:approve" ctx.Permissions)
        | None -> failwith "session token did not resolve"

[<Fact>]
let ``login with a wrong password fails and no session is created`` () =
    let auth = AuthService(AstraStore(), testConfig)
    auth.EnsureAdmin() |> ignore
    match auth.Login("admin", "nope") with
    | Ok _ -> failwith "expected login failure"
    | Error _ -> ()

[<Fact>]
let ``logout invalidates the session token`` () =
    let auth = AuthService(AstraStore(), testConfig)
    auth.EnsureAdmin() |> ignore
    let session = auth.Login("admin", "test-admin-pw") |> Result.toOption |> Option.get
    auth.Logout session.Token
    Assert.True((auth.ContextFromToken session.Token).IsNone)

[<Fact>]
let ``analyst role cannot approve but can request and read`` () =
    let auth = AuthService(AstraStore(), testConfig)
    auth.EnsureAdmin() |> ignore
    auth.CreateUser("casey", "analyst-pw", "Casey", "analyst", "admin") |> ignore
    let session = auth.Login("casey", "analyst-pw") |> Result.toOption |> Option.get
    Assert.True(hasPermission "read:api" session.Permissions)
    Assert.True(hasPermission "respond:request" session.Permissions)
    Assert.True(hasPermission "triage:write" session.Permissions)
    Assert.False(hasPermission "respond:approve" session.Permissions)
    Assert.False(hasPermission "admin:manage" session.Permissions)

[<Fact>]
let ``api key resolves to its role context and revocation-by-expiry is honored`` () =
    let auth = AuthService(AstraStore(), testConfig)
    match auth.CreateApiKey("ci-reader", "readonly", None, "admin") with
    | Error e -> failwithf "create key failed: %s" e
    | Ok (_, plaintext) ->
        match auth.ContextFromApiKey plaintext with
        | Some ctx ->
            Assert.Equal("api_key", ctx.Kind)
            Assert.True(hasPermission "read:api" ctx.Permissions)
            Assert.False(hasPermission "triage:write" ctx.Permissions)
        | None -> failwith "api key did not resolve"
    match auth.CreateApiKey("expired", "readonly", Some (DateTimeOffset.UtcNow.AddMinutes -1.0), "admin") with
    | Ok (_, plaintext) -> Assert.True((auth.ContextFromApiKey plaintext).IsNone)
    | Error e -> failwithf "create key failed: %s" e

// -------------------------------------------------------------- connectors

let private mkConnector name kind sim : ResponseConnector =
    { ConnectorName = name; Kind = kind; ConfigRef = "TEST_ENDPOINT"; SimulationMode = sim; Status = "active" }

/// Test double that records deliveries instead of touching the network.
type private RecordingDispatcher() =
    member val Delivered : (string * string) list = [] with get, set
    interface Astra.Server.Connectors.IConnectorDispatcher with
        member this.Deliver(c, a) =
            this.Delivered <- (c.ConnectorName, ResponseActionKind.label a.Kind) :: this.Delivered
            Ok "delivered (test)"

[<Fact>]
let ``connector selection prefers a live connector over a simulated one`` () =
    let store = AstraStore()
    store.UpsertConnector (mkConnector "fw-sim" ConnectorKind.Firewall true)
    store.UpsertConnector (mkConnector "fw-live" ConnectorKind.Firewall false)
    match Astra.Server.Connectors.selectConnector store ResponseActionKind.BlockIp with
    | Some c -> Assert.Equal("fw-live", c.ConnectorName)
    | None -> failwith "expected a connector"

[<Fact>]
let ``approval delivers through a live connector for real`` () =
    let store = AstraStore()
    store.UpsertConnector (mkConnector "edge-fw" ConnectorKind.Firewall false)   // live
    let dispatcher = RecordingDispatcher()
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp "203.0.113.66" "C2" [] [] "analyst"
    match Astra.Server.Response.approveWith (Some (dispatcher :> Astra.Server.Connectors.IConnectorDispatcher)) store action.ActionId "lead" with
    | Error e -> failwithf "approve failed: %s" e
    | Ok updated ->
        Assert.Equal(ResponseStatus.Completed, updated.Status)
        Assert.False(updated.Simulation)
        Assert.Equal(Some "edge-fw", updated.ConnectorName)
        Assert.StartsWith("executed", defaultArg updated.Result "")
        Assert.Single(dispatcher.Delivered) |> ignore

[<Fact>]
let ``approval stays simulated when the matching connector is in simulation mode`` () =
    let store = AstraStore()
    store.UpsertConnector (mkConnector "edge-fw" ConnectorKind.Firewall true)    // simulation
    let dispatcher = RecordingDispatcher()
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp "203.0.113.66" "C2" [] [] "analyst"
    match Astra.Server.Response.approveWith (Some (dispatcher :> Astra.Server.Connectors.IConnectorDispatcher)) store action.ActionId "lead" with
    | Error e -> failwithf "approve failed: %s" e
    | Ok updated ->
        Assert.True(updated.Simulation)
        Assert.StartsWith("SIMULATED:", defaultArg updated.Result "")
        Assert.Empty(dispatcher.Delivered)

[<Fact>]
let ``failed live delivery marks the action failed rather than lying`` () =
    let store = AstraStore()
    store.UpsertConnector (mkConnector "edge-fw" ConnectorKind.Firewall false)
    let failing =
        { new Astra.Server.Connectors.IConnectorDispatcher with
            member _.Deliver(_, _) = Error "connection refused" }
    let action = Astra.Server.Response.request store ResponseActionKind.BlockIp "203.0.113.66" "C2" [] [] "analyst"
    match Astra.Server.Response.approveWith (Some failing) store action.ActionId "lead" with
    | Error e -> failwithf "approve returned error: %s" e
    | Ok updated ->
        Assert.Equal(ResponseStatus.Failed, updated.Status)
        Assert.Contains("connection refused", defaultArg updated.Result "")

// --------------------------------------------------------------- telemetry

[<Fact>]
let ``null telemetry sink reports in-memory and healthy`` () =
    let sink = Astra.Server.Telemetry.NullTelemetrySink() :> Astra.Server.Telemetry.ITelemetrySink
    sink.Persist []
    let s = sink.Status
    Assert.Equal("in-memory", s.Backend)
    Assert.True(s.Healthy)

[<Fact>]
let ``telemetry factory selects backend from config`` () =
    let logger = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance
    let none = Astra.Server.Telemetry.create testConfig logger
    Assert.Equal("in-memory", none.Status.Backend)
    let ch = Astra.Server.Telemetry.create { testConfig with ClickHouseUrl = "http://localhost:8123" } logger
    Assert.Equal("clickhouse", ch.Status.Backend)
    let os = Astra.Server.Telemetry.create { testConfig with OpenSearchUrl = "http://localhost:9200" } logger
    Assert.Equal("opensearch", os.Status.Backend)
