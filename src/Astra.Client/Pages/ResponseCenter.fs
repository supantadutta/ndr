module Astra.Client.Pages.ResponseCenter

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Response Center: analyst-approved, simulation-first response orchestration.
/// Pending actions await human approval; destructive actions are forced into
/// simulation mode so nothing touches the network without an explicit decision.

let private statusColor = function
    | "pending_approval" -> "#ffd166"
    | "completed" -> "#3ddc97"
    | "rejected" -> "#ff4d6d"
    | "failed" -> "#ff4d6d"
    | _ -> Theme.textMuted

let private kindOptions =
    [ "block_ip", "Block IP"
      "block_domain", "Block domain"
      "block_host", "Block host"
      "isolate_host_sim", "Isolate host (sim)"
      "disable_account_sim", "Disable account (sim)"
      "create_ticket", "Create ticket"
      "send_webhook", "Send webhook"
      "export_siem", "Export to SIEM"
      "add_threat_indicator", "Add threat indicator" ]

[<ReactComponent>]
let ResponseCenter () =
    let actions, updatedAt, refreshActions = useLiveData Api.getResponseActions 8000
    let connectors, _, refreshConn = useLiveData Api.getConnectors 20000
    let (reqKind, setReqKind) = React.useState "block_ip"
    let (reqTarget, setReqTarget) = React.useState ""
    let (reqReason, setReqReason) = React.useState ""
    let refreshAll () = refreshActions (); refreshConn ()

    let request () =
        if reqTarget.Trim() <> "" then
            Api.requestResponseAction reqKind (reqTarget.Trim()) (if reqReason.Trim() = "" then "analyst-requested containment" else reqReason.Trim()) "analyst"
            |> Promise.map (fun _ -> setReqTarget ""; setReqReason ""; refreshAll ()) |> Promise.start

    let decide (id: string) (approve: bool) =
        (if approve then Api.approveAction id "analyst" else Api.rejectAction id "analyst")
        |> Promise.map (fun _ -> refreshAll ()) |> Promise.start

    let actionButton (label: string) (color: string) (onClick: unit -> unit) =
        Html.button [
            prop.onClick (fun _ -> onClick ())
            prop.style [ style.padding (5, 12); style.backgroundColor "transparent"; style.color color
                         style.border (1, borderStyle.solid, color); style.borderRadius 6; style.fontSize 12
                         style.fontWeight 600; style.cursor.pointer ]
            prop.text label
        ]

    Html.div [
        pageHeaderLive "Response Center" "Analyst-approved, simulation-first response orchestration" updatedAt refreshAll

        // request an action
        panelTitled "Request response action" [
            Html.div [
                prop.style [ style.display.flex; style.gap 8; style.flexWrap.wrap; style.alignItems.center ]
                prop.children [
                    Html.select [ prop.value reqKind; prop.onChange (fun (v: string) -> setReqKind v)
                                  prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6 ]
                                  prop.children [ for (v, lbl) in kindOptions -> Html.option [ prop.value v; prop.text lbl ] ] ]
                    Html.input [ prop.value reqTarget; prop.onChange (fun (v: string) -> setReqTarget v); prop.placeholder "target (IP / domain / host / indicator)"
                                 prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6; style.minWidth 240 ] ]
                    Html.input [ prop.value reqReason; prop.onChange (fun (v: string) -> setReqReason v); prop.placeholder "reason"
                                 prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6; style.minWidth 200 ] ]
                    Html.button [ prop.onClick (fun _ -> request ())
                                  prop.style [ style.padding (8, 16); style.backgroundColor Theme.accent; style.color "#0b0f1a"; style.border (0, borderStyle.none, ""); style.borderRadius 6; style.fontWeight 600; style.cursor.pointer ]
                                  prop.text "Request" ]
                ]
            ]
            Html.div [ prop.style [ style.fontSize 11; style.color Theme.textMuted; style.marginTop 10 ]
                       prop.text "Destructive actions are forced into simulation mode and require explicit analyst approval before any effect." ]
        ]

        // pending approvals
        Html.div [
            prop.style [ style.marginTop 14 ]
            prop.children [
                panelTitled "Pending approvals" [
                    remote actions "actions" (fun list ->
                        let pending = list |> List.filter (fun a -> a.Status = "pending_approval")
                        if pending.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No actions awaiting approval." ]
                        else
                        Html.div [
                            prop.style [ style.display.flex; style.flexDirection.column; style.gap 10 ]
                            prop.children [
                                for a in pending ->
                                    Html.div [
                                        prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.alignItems.center; style.gap 12
                                                     style.padding 12; style.backgroundColor Theme.bgPanelAlt; style.borderRadius 8
                                                     style.border (1, borderStyle.solid, Theme.border) ]
                                        prop.children [
                                            Html.div [
                                                prop.children [
                                                    Html.div [ prop.style [ style.display.flex; style.alignItems.center; style.gap 8; style.marginBottom 4 ]
                                                               prop.children [
                                                                   Html.span [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text a.Kind ]
                                                                   Html.span [ prop.style [ style.fontFamily "monospace"; style.color Theme.accent ]; prop.text a.Target ]
                                                                   (if a.Simulation then badge "simulation" "#ffd166" else badge "live" "#ff4d6d") ] ]
                                                    Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text (sprintf "%s · requested by %s" a.Reason a.RequestedBy) ]
                                                ]
                                            ]
                                            Html.div [
                                                prop.style [ style.display.flex; style.gap 8 ]
                                                prop.children [
                                                    actionButton "Approve" "#3ddc97" (fun () -> decide a.ActionId true)
                                                    actionButton "Reject" "#ff4d6d" (fun () -> decide a.ActionId false)
                                                ]
                                            ]
                                        ]
                                    ]
                            ]
                        ])
                ]
            ]
        ]

        // history + connectors
        Html.div [
            prop.style [ style.marginTop 14; style.display.grid; style.gridTemplateColumns [ length.fr 2; length.fr 1 ]; style.gap 14 ]
            prop.children [
                panelTitled "Action history" [
                    remote actions "actions" (fun list ->
                        let history = list |> List.filter (fun a -> a.Status <> "pending_approval")
                        if history.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No completed actions yet." ]
                        else
                        table [ "When"; "Action"; "Target"; "Status"; "Mode"; "Result" ] [
                            for a in history ->
                                Html.tr [
                                    tdText (a.CreatedAt.Substring(0, 19).Replace("T", " "))
                                    tdText a.Kind
                                    td [ Html.span [ prop.style [ style.fontFamily "monospace"; style.color Theme.textPrimary ]; prop.text a.Target ] ]
                                    td [ badge a.Status (statusColor a.Status) ]
                                    td [ (if a.Simulation then badge "sim" "#ffd166" else badge "live" "#ff4d6d") ]
                                    tdText (defaultArg a.Result "—")
                                ]
                        ])
                ]
                panelTitled "Connectors" [
                    remote connectors "connectors" (fun list ->
                        if list.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No connectors configured." ]
                        else
                        Html.div [
                            prop.style [ style.display.flex; style.flexDirection.column; style.gap 8 ]
                            prop.children [
                                for c in list ->
                                    Html.div [
                                        prop.style [ style.padding 10; style.backgroundColor Theme.bgPanelAlt; style.borderRadius 6 ]
                                        prop.children [
                                            Html.div [ prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.alignItems.center ]
                                                       prop.children [
                                                           Html.div [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text c.Name ]
                                                           badge c.Status (Theme.statusColor c.Status) ] ]
                                            Html.div [ prop.style [ style.display.flex; style.alignItems.center; style.gap 8; style.marginTop 4 ]
                                                       prop.children [
                                                           Html.span [ prop.style [ style.fontSize 11; style.color Theme.textMuted ]; prop.text c.Kind ]
                                                           (if c.SimulationMode then badge "simulation" "#ffd166" else badge "live" "#ff4d6d") ] ]
                                            Html.div [ prop.style [ style.marginTop 8 ]
                                                       prop.children [
                                                           actionButton
                                                               (if c.SimulationMode then "Enable live delivery" else "Return to simulation")
                                                               (if c.SimulationMode then "#ff8c42" else "#3ddc97")
                                                               (fun () ->
                                                                   Api.setConnectorMode c.Name (not c.SimulationMode) "analyst"
                                                                   |> Promise.map (fun _ -> refreshAll ()) |> Promise.start) ] ]
                                        ]
                                    ]
                            ]
                        ])
                ]
            ]
        ]
    ]
