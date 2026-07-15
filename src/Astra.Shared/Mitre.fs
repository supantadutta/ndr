namespace Astra.Shared

/// Original mapping layer onto the public MITRE ATT&CK® knowledge base
/// (tactic/technique identifiers are public taxonomy references).

[<RequireQualifiedAccess>]
type MitreTactic =
    | Reconnaissance
    | ResourceDevelopment
    | InitialAccess
    | Execution
    | Persistence
    | PrivilegeEscalation
    | DefenseEvasion
    | CredentialAccess
    | Discovery
    | LateralMovement
    | Collection
    | CommandAndControl
    | Exfiltration
    | Impact

type MitreTechnique =
    { TechniqueId: string        // e.g. "T1046"
      TechniqueName: string      // e.g. "Network Service Discovery"
      Tactic: MitreTactic }

[<RequireQualifiedAccess>]
type KillChainStage =
    | Reconnaissance
    | Delivery
    | Exploitation
    | Installation
    | CommandAndControl
    | LateralMovement
    | ActionOnObjectives

module MitreTactic =
    let label = function
        | MitreTactic.Reconnaissance -> "Reconnaissance"
        | MitreTactic.ResourceDevelopment -> "Resource Development"
        | MitreTactic.InitialAccess -> "Initial Access"
        | MitreTactic.Execution -> "Execution"
        | MitreTactic.Persistence -> "Persistence"
        | MitreTactic.PrivilegeEscalation -> "Privilege Escalation"
        | MitreTactic.DefenseEvasion -> "Defense Evasion"
        | MitreTactic.CredentialAccess -> "Credential Access"
        | MitreTactic.Discovery -> "Discovery"
        | MitreTactic.LateralMovement -> "Lateral Movement"
        | MitreTactic.Collection -> "Collection"
        | MitreTactic.CommandAndControl -> "Command and Control"
        | MitreTactic.Exfiltration -> "Exfiltration"
        | MitreTactic.Impact -> "Impact"

    let all =
        [ MitreTactic.Reconnaissance; MitreTactic.ResourceDevelopment; MitreTactic.InitialAccess
          MitreTactic.Execution; MitreTactic.Persistence; MitreTactic.PrivilegeEscalation
          MitreTactic.DefenseEvasion; MitreTactic.CredentialAccess; MitreTactic.Discovery
          MitreTactic.LateralMovement; MitreTactic.Collection; MitreTactic.CommandAndControl
          MitreTactic.Exfiltration; MitreTactic.Impact ]

module KillChainStage =
    let label = function
        | KillChainStage.Reconnaissance -> "reconnaissance"
        | KillChainStage.Delivery -> "delivery"
        | KillChainStage.Exploitation -> "exploitation"
        | KillChainStage.Installation -> "installation"
        | KillChainStage.CommandAndControl -> "command_and_control"
        | KillChainStage.LateralMovement -> "lateral_movement"
        | KillChainStage.ActionOnObjectives -> "action_on_objectives"

    /// Ordinal used by scoring for kill-chain progression modifiers.
    let ordinal = function
        | KillChainStage.Reconnaissance -> 1
        | KillChainStage.Delivery -> 2
        | KillChainStage.Exploitation -> 3
        | KillChainStage.Installation -> 4
        | KillChainStage.CommandAndControl -> 5
        | KillChainStage.LateralMovement -> 6
        | KillChainStage.ActionOnObjectives -> 7
