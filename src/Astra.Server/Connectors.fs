module Astra.Server.Connectors

open System
open System.Net.Http
open System.Net.Sockets
open System.Text
open Microsoft.Extensions.Logging
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Response connector delivery. Connectors start in simulation mode; an admin
/// flips a connector to live (SimulationMode=false) to enable real delivery.
/// Secrets are never stored: a connector's ConfigRef names an environment
/// variable holding its endpoint URL, and `<ConfigRef>_TOKEN` (optional) holds
/// its auth token. When a matching live connector exists, an approved action is
/// delivered for real; otherwise it is simulated.
/// ============================================================================

/// Connector kinds that can carry out a given action kind.
let categoryFor (kind: ResponseActionKind) : ConnectorKind list =
    match kind with
    | ResponseActionKind.BlockIp | ResponseActionKind.BlockDomain
    | ResponseActionKind.BlockHost | ResponseActionKind.AddBlocklistFeed ->
        [ ConnectorKind.Firewall ]
    | ResponseActionKind.IsolateHostSim -> [ ConnectorKind.Edr ]
    | ResponseActionKind.DisableAccountSim -> [ ConnectorKind.Soar; ConnectorKind.Edr ]
    | ResponseActionKind.CreateTicket -> [ ConnectorKind.Soar ]
    | ResponseActionKind.SendEmail | ResponseActionKind.SendWebhook -> [ ConnectorKind.Webhook ]
    | ResponseActionKind.ExportSiem ->
        [ ConnectorKind.SplunkHec; ConnectorKind.SentinelStyle; ConnectorKind.ElasticOpenSearch
          ConnectorKind.SyslogTcp; ConnectorKind.SyslogTls ]
    | ResponseActionKind.ExportSoar -> [ ConnectorKind.Soar ]
    | ResponseActionKind.AddThreatIndicator -> []

/// Pick an enabled connector able to carry out this action, preferring a live one.
let selectConnector (store: AstraStore) (kind: ResponseActionKind) : ResponseConnector option =
    let cats = categoryFor kind
    let candidates =
        store.Connectors
        |> List.filter (fun c -> c.Status <> "disabled" && List.contains c.Kind cats)
    // prefer a live (enforcing) connector; fall back to a simulation-mode one
    match candidates |> List.tryFind (fun c -> not c.SimulationMode) with
    | Some c -> Some c
    | None -> candidates |> List.tryHead

/// The delivery outcome for an approved, live action.
type IConnectorDispatcher =
    /// Deliver the action through the connector. Returns a human-readable result
    /// on success or an error string on failure.
    abstract member Deliver: ResponseConnector * ResponseAction -> Result<string, string>

/// A ConfigRef is an environment-variable name, optionally written "env:NAME".
let envKeyOf (configRef: string) =
    if configRef.StartsWith "env:" then configRef.Substring 4 else configRef

let private envRef (configRef: string) =
    match Environment.GetEnvironmentVariable(envKeyOf configRef) with
    | null | "" -> None
    | v -> Some v

/// Build a compact JSON payload describing the action for downstream systems.
let private actionPayload (a: ResponseAction) : string =
    Astra.Server.Json.serialize
        {| action = ResponseActionKind.label a.Kind
           target = a.Target
           reason = a.Reason
           requestedBy = a.RequestedBy
           approvedBy = a.ApprovedBy
           actionId = string a.ActionId
           at = DateTimeOffset.UtcNow.ToString("o") |}

/// Real dispatcher: performs the actual network delivery per connector kind.
type RealConnectorDispatcher(logger: ILogger) =
    let http = new HttpClient(Timeout = TimeSpan.FromSeconds 10.0)

    let postJson (url: string) (auth: (string * string) option) (body: string) : Result<string, string> =
        try
            use req = new HttpRequestMessage(HttpMethod.Post, url)
            req.Content <- new StringContent(body, Encoding.UTF8, "application/json")
            match auth with
            | Some (scheme, token) -> req.Headers.Authorization <- Headers.AuthenticationHeaderValue(scheme, token)
            | None -> ()
            let resp = http.Send req
            let respBody = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if resp.IsSuccessStatusCode then Ok (sprintf "delivered (HTTP %d)" (int resp.StatusCode))
            else Error (sprintf "HTTP %d: %s" (int resp.StatusCode) (respBody.Substring(0, min 200 respBody.Length)))
        with ex -> Error ex.Message

    let sendSyslog (hostPort: string) (line: string) : Result<string, string> =
        try
            let parts = hostPort.Replace("tcp://", "").Split(':')
            let host = parts.[0]
            let port = if parts.Length > 1 then int parts.[1] else 514
            use client = new TcpClient()
            client.Connect(host, port)
            use stream = client.GetStream()
            let bytes = Encoding.UTF8.GetBytes(line + "\n")
            stream.Write(bytes, 0, bytes.Length)
            Ok (sprintf "syslog line sent to %s:%d" host port)
        with ex -> Error ex.Message

    interface IConnectorDispatcher with
        member _.Deliver(connector: ResponseConnector, action: ResponseAction) =
            match envRef connector.ConfigRef with
            | None ->
                Error (sprintf "connector '%s' endpoint env '%s' is not set" connector.ConnectorName connector.ConfigRef)
            | Some endpoint ->
                let token = envRef (envKeyOf connector.ConfigRef + "_TOKEN")
                let result =
                    match connector.Kind with
                    | ConnectorKind.Webhook ->
                        postJson endpoint (token |> Option.map (fun t -> "Bearer", t)) (actionPayload action)
                    | ConnectorKind.SplunkHec ->
                        let url = endpoint.TrimEnd('/') + "/services/collector/event"
                        let body = Astra.Server.Json.serialize {| event = actionPayload action; sourcetype = "astra:response" |}
                        postJson url (token |> Option.map (fun t -> "Splunk", t)) body
                    | ConnectorKind.ElasticOpenSearch ->
                        postJson (endpoint.TrimEnd('/') + "/astra-response/_doc") None (actionPayload action)
                    | ConnectorKind.SyslogTcp | ConnectorKind.SyslogTls ->
                        sendSyslog endpoint (sprintf "CEF:0|AstraNDR|Astra|1.0|response|%s|5|act=%s dst=%s"
                                                (ResponseActionKind.label action.Kind) (ResponseActionKind.label action.Kind) action.Target)
                    | ConnectorKind.Firewall | ConnectorKind.Edr | ConnectorKind.Soar
                    | ConnectorKind.SentinelStyle | ConnectorKind.Kafka ->
                        // Generic REST delivery for enforcement/ticketing back-ends.
                        postJson endpoint (token |> Option.map (fun t -> "Bearer", t)) (actionPayload action)
                match result with
                | Ok msg -> logger.LogInformation("Connector {Name} delivered {Action}: {Msg}", connector.ConnectorName, ResponseActionKind.label action.Kind, msg)
                | Error e -> logger.LogWarning("Connector {Name} delivery failed: {Err}", connector.ConnectorName, e)
                result

/// Simulation dispatcher: never touches the network (used in tests / demo).
type SimulationDispatcher() =
    interface IConnectorDispatcher with
        member _.Deliver(connector, action) =
            Ok (sprintf "SIMULATED via %s: would %s '%s'" connector.ConnectorName (ResponseActionKind.label action.Kind) action.Target)
