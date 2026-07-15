module Astra.Server.Auth

open System
open System.Collections.Concurrent
open System.Security.Cryptography
open Astra.Shared
open Astra.Server.Store

/// ============================================================================
/// Authentication + RBAC. Production deployments set ASTRA_AUTH_ENABLED=true,
/// after which every API route requires either a session token (issued by
/// /api/auth/login) or an API key. Roles carry a permission list; routes assert
/// a required permission. Passwords and API keys are stored only as PBKDF2
/// hashes — never plaintext. With auth disabled the middleware is a pass-through
/// so the demo/lab console keeps working unauthenticated.
/// ============================================================================

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

type Role =
    { Name: string
      Permissions: string list }

type User =
    { UserId: Guid
      Username: string
      DisplayName: string
      Email: string option
      PasswordHash: string
      RoleName: string
      Disabled: bool
      CreatedAt: DateTimeOffset
      LastLogin: DateTimeOffset option }

type Session =
    { Token: string
      UserId: Guid
      Username: string
      RoleName: string
      Permissions: string list
      IssuedAt: DateTimeOffset
      ExpiresAt: DateTimeOffset }

type ApiKey =
    { KeyId: Guid
      Name: string
      KeyHash: string
      RoleName: string
      Permissions: string list
      CreatedAt: DateTimeOffset
      ExpiresAt: DateTimeOffset option
      Revoked: bool }

/// The resolved identity attached to an authenticated request.
type AuthContext =
    { Subject: string          // username or api-key name
      Kind: string             // "user" | "api_key"
      RoleName: string
      Permissions: string list }

// ---------------------------------------------------------------------------
// Default roles (mirror db/migrations 0001 roles seed)
// ---------------------------------------------------------------------------

let defaultRoles =
    [ { Name = "admin";    Permissions = [ "*" ] }
      { Name = "analyst";  Permissions = [ "read:*"; "triage:*"; "respond:request" ] }
      { Name = "readonly"; Permissions = [ "read:*" ] }
      { Name = "sensor";   Permissions = [ "ingest:events"; "ingest:heartbeat" ] } ]

/// Does a held permission satisfy a required one? Supports "*" and "prefix:*".
let permissionMatches (held: string) (required: string) =
    held = "*"
    || held = required
    || (held.EndsWith ":*" && required.StartsWith(held.Substring(0, held.Length - 1)))

let hasPermission (required: string) (perms: string list) =
    perms |> List.exists (fun h -> permissionMatches h required)

// ---------------------------------------------------------------------------
// Hashing (PBKDF2-SHA256) + token generation
// ---------------------------------------------------------------------------

module Hashing =
    let private iterations = 120_000
    let private saltLen = 16
    let private keyLen = 32

    let hash (secret: string) : string =
        let salt = RandomNumberGenerator.GetBytes saltLen
        use kdf = new Rfc2898DeriveBytes(secret, salt, iterations, HashAlgorithmName.SHA256)
        let key = kdf.GetBytes keyLen
        sprintf "pbkdf2$sha256$%d$%s$%s" iterations (Convert.ToBase64String salt) (Convert.ToBase64String key)

    let verify (secret: string) (encoded: string) : bool =
        try
            match encoded.Split('$') with
            | [| "pbkdf2"; "sha256"; iters; saltB64; keyB64 |] ->
                let salt = Convert.FromBase64String saltB64
                let expected = Convert.FromBase64String keyB64
                use kdf = new Rfc2898DeriveBytes(secret, salt, int iters, HashAlgorithmName.SHA256)
                let actual = kdf.GetBytes expected.Length
                CryptographicOperations.FixedTimeEquals(ReadOnlySpan<byte>(actual), ReadOnlySpan<byte>(expected))
            | _ -> false
        with _ -> false

module Tokens =
    /// URL-safe random token.
    let newToken () =
        Convert.ToBase64String(RandomNumberGenerator.GetBytes 32)
              .Replace("+", "-").Replace("/", "_").TrimEnd('=')

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

type AuthService(store: AstraStore, config: Astra.Server.Config.ServerConfig) =
    let roles = ConcurrentDictionary<string, Role>()
    let users = ConcurrentDictionary<string, User>()          // keyed by username (lower)
    let sessions = ConcurrentDictionary<string, Session>()    // keyed by token
    let apiKeys = ConcurrentDictionary<Guid, ApiKey>()

    do defaultRoles |> List.iter (fun r -> roles.[r.Name] <- r)

    let permsFor roleName =
        match roles.TryGetValue roleName with
        | true, r -> r.Permissions
        | _ -> []

    let audit actor action subjectKind subjectId =
        store.Audit
            { At = DateTimeOffset.UtcNow; Actor = actor; ActorKind = "user"
              Action = action; SubjectKind = subjectKind; SubjectId = subjectId; Details = Map.empty }

    member _.AuthEnabled = config.AuthEnabled
    member _.Roles = roles.Values |> Seq.toList
    member _.Users = users.Values |> Seq.toList

    /// Create the bootstrap admin account if no users exist yet.
    member _.EnsureAdmin() =
        if users.IsEmpty then
            let u =
                { UserId = Guid.NewGuid(); Username = config.AdminUsername
                  DisplayName = "Administrator"; Email = None
                  PasswordHash = Hashing.hash config.AdminPassword
                  RoleName = "admin"; Disabled = false
                  CreatedAt = DateTimeOffset.UtcNow; LastLogin = None }
            users.[u.Username.ToLowerInvariant()] <- u
            u.Username |> Some
        else None

    member _.CreateUser(username: string, password: string, displayName: string, roleName: string, actor: string) : Result<User, string> =
        if String.IsNullOrWhiteSpace username || String.IsNullOrWhiteSpace password then Error "username and password are required"
        elif not (roles.ContainsKey roleName) then Error (sprintf "unknown role '%s'" roleName)
        elif users.ContainsKey (username.ToLowerInvariant()) then Error "user already exists"
        else
            let u =
                { UserId = Guid.NewGuid(); Username = username; DisplayName = displayName
                  Email = None; PasswordHash = Hashing.hash password; RoleName = roleName
                  Disabled = false; CreatedAt = DateTimeOffset.UtcNow; LastLogin = None }
            users.[username.ToLowerInvariant()] <- u
            audit actor "auth.create_user" "user" username
            Ok u

    /// Authenticate a username/password, returning a fresh session on success.
    member _.Login(username: string, password: string) : Result<Session, string> =
        match users.TryGetValue (username.ToLowerInvariant()) with
        | true, u when not u.Disabled && Hashing.verify password u.PasswordHash ->
            let now = DateTimeOffset.UtcNow
            let session =
                { Token = Tokens.newToken (); UserId = u.UserId; Username = u.Username
                  RoleName = u.RoleName; Permissions = permsFor u.RoleName
                  IssuedAt = now; ExpiresAt = now.Add config.SessionTtl }
            sessions.[session.Token] <- session
            users.[username.ToLowerInvariant()] <- { u with LastLogin = Some now }
            audit u.Username "auth.login" "session" u.Username
            Ok session
        | _ -> Error "invalid credentials"

    member _.Logout(token: string) =
        match sessions.TryRemove token with
        | true, s -> audit s.Username "auth.logout" "session" s.Username
        | _ -> ()

    /// Resolve a bearer session token to an AuthContext (None if expired/invalid).
    member _.ContextFromToken(token: string) : AuthContext option =
        match sessions.TryGetValue token with
        | true, s when s.ExpiresAt > DateTimeOffset.UtcNow ->
            Some { Subject = s.Username; Kind = "user"; RoleName = s.RoleName; Permissions = s.Permissions }
        | true, _ -> sessions.TryRemove token |> ignore; None   // expired: evict
        | _ -> None

    /// Mint an API key. Returns the plaintext once; only the hash is stored.
    member _.CreateApiKey(name: string, roleName: string, expiresAt: DateTimeOffset option, actor: string) : Result<Guid * string, string> =
        if not (roles.ContainsKey roleName) then Error (sprintf "unknown role '%s'" roleName)
        else
            let plaintext = "ak_" + Tokens.newToken ()
            let key =
                { KeyId = Guid.NewGuid(); Name = name; KeyHash = Hashing.hash plaintext
                  RoleName = roleName; Permissions = permsFor roleName
                  CreatedAt = DateTimeOffset.UtcNow; ExpiresAt = expiresAt; Revoked = false }
            apiKeys.[key.KeyId] <- key
            audit actor "auth.create_api_key" "api_key" name
            Ok (key.KeyId, plaintext)

    member _.ContextFromApiKey(presented: string) : AuthContext option =
        apiKeys.Values
        |> Seq.tryFind (fun k ->
            not k.Revoked
            && (k.ExpiresAt |> Option.forall (fun e -> e > DateTimeOffset.UtcNow))
            && Hashing.verify presented k.KeyHash)
        |> Option.map (fun k -> { Subject = k.Name; Kind = "api_key"; RoleName = k.RoleName; Permissions = k.Permissions })

    member _.ApiKeys = apiKeys.Values |> Seq.toList

    /// Drop expired sessions (called opportunistically).
    member _.PruneExpired() =
        let now = DateTimeOffset.UtcNow
        for kv in sessions do
            if kv.Value.ExpiresAt <= now then sessions.TryRemove kv.Key |> ignore
