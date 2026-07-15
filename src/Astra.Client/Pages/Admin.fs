module Astra.Client.Pages.Admin

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Admin settings — live audit log + telemetry persistence status.

[<ReactComponent>]
let Admin () =
    let audit, updatedAt, refreshAudit = useLiveData Api.getAudit 10000
    let telemetry, _, refreshTelemetry = useLiveData Api.getTelemetryStatus 15000
    let refresh () = refreshAudit (); refreshTelemetry ()

    Html.div [
        pageHeaderLive "Admin" "Audit trail and platform health" updatedAt refresh

        panelTitled "Telemetry persistence" [
            remote telemetry "telemetry status" (fun t ->
                Html.div [
                    prop.style [ style.display.flex; style.gap 24; style.flexWrap.wrap; style.alignItems.center ]
                    prop.children [
                        Html.div [
                            prop.style [ style.display.flex; style.alignItems.center; style.gap 8 ]
                            prop.children [
                                Html.span [ prop.style [ style.width 10; style.height 10; style.borderRadius 5; style.display.inlineBlock
                                                         style.backgroundColor (if t.Healthy then "#3ddc97" else "#ff4d6d") ] ]
                                Html.span [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text t.Backend ]
                                (if t.Endpoint <> "" then Html.span [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text t.Endpoint ] else Html.none)
                            ]
                        ]
                        Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]
                                   prop.text (sprintf "persisted %d · failed %d" t.Persisted t.Failed) ]
                        (match t.LastError with
                         | Some e -> Html.div [ prop.style [ style.fontSize 12; style.color "#ff8c42" ]; prop.text e ]
                         | None -> Html.none)
                        (if t.Backend = "in-memory" then
                            Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]
                                       prop.text "Set ASTRA_CLICKHOUSE_URL or ASTRA_OPENSEARCH_URL for durable event storage." ]
                         else Html.none)
                    ]
                ])
        ]

        Html.div [
            prop.style [ style.marginTop 14 ]
            prop.children [
                panelTitled "Audit log" [
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
        ]
    ]
