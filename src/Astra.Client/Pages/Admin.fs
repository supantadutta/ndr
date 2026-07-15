module Astra.Client.Pages.Admin

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Admin settings — Phase 3 delivers the live audit log; users/roles/coverage
/// editing arrive with the auth layer in Phase 5.

[<ReactComponent>]
let Admin () =
    let audit, updatedAt, refresh = useLiveData Api.getAudit 10000

    Html.div [
        pageHeaderLive "Admin — Audit Log" "Every triage, tuning and governance action is recorded" updatedAt refresh
        panel [
            remote audit "audit" (fun entries ->
                if entries.IsEmpty then
                    Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No audited actions yet. Triage a detection or tune a rule to see entries." ]
                else
                table [ "Time"; "Actor"; "Action"; "Subject" ] [
                    for e in entries ->
                        Html.tr [
                            tdText e.At
                            tdText e.Actor
                            td [ badge (e.Action.Replace(".", " ")) Theme.accent ]
                            tdText (sprintf "%s %s" e.SubjectKind (e.SubjectId.Substring(0, min 8 e.SubjectId.Length))) ]
                ])
        ]
    ]
