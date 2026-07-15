module Astra.Client.Pages.AttackGraph

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Attack graph page: pick a prioritized entity, render its radial investigation
/// graph (host ↔ peers ↔ domains ↔ detections). Legend explains node kinds.

[<ReactComponent>]
let AttackGraph () =
    let (queue, setQueue) = React.useState<Result<EntityQueuePage, string> option> None
    let (selected, setSelected) = React.useState<string option> None
    let (graph, setGraph) = React.useState<Result<InvestigationGraph, string> option> None

    React.useEffectOnce(fun () ->
        Api.getEntityQueue 1 |> Promise.map (fun r ->
            setQueue (Some r)
            match r with
            | Ok p -> (match p.Items with first :: _ -> setSelected (Some first.EntityId) | [] -> ())
            | _ -> ()) |> Promise.start)

    React.useEffect((fun () ->
        match selected with
        | Some id -> setGraph None; Api.getGraphEntity id |> Promise.map (Some >> setGraph) |> Promise.start
        | None -> ()), [| box selected |])

    let legend =
        [ "host", "#4c8dff"; "external ip", "#ff8c42"; "domain", "#a78bfa"; "detection", "#ff4d6d" ]

    Html.div [
        pageHeader "Attack Graph" "Radial investigation graph around a prioritized entity"
        Html.div [
            prop.style [ style.display.grid; style.gridTemplateColumns [ length.px 260; length.fr 1 ]; style.gap 14 ]
            prop.children [
                // entity picker
                panelTitled "Entities" [
                    remote queue "entities" (fun p ->
                        if p.Items.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No entities." ]
                        else
                        Html.div [
                            prop.style [ style.display.flex; style.flexDirection.column; style.gap 4 ]
                            prop.children [
                                for e in p.Items ->
                                    Html.button [
                                        prop.onClick (fun _ -> setSelected (Some e.EntityId))
                                        prop.style [
                                            style.textAlign.left; style.padding (8, 10); style.borderRadius 6; style.cursor.pointer
                                            style.border (1, borderStyle.solid, (if selected = Some e.EntityId then Theme.accent else Theme.border))
                                            style.backgroundColor (if selected = Some e.EntityId then Theme.accentDim else Theme.bgPanelAlt)
                                            style.color Theme.textPrimary; style.fontSize 13
                                            style.display.flex; style.justifyContent.spaceBetween; style.alignItems.center
                                        ]
                                        prop.children [ Html.span [ prop.text e.DisplayName ]; scoreChip e.Urgency ]
                                    ]
                            ]
                        ])
                ]
                // graph
                panel [
                    Html.div [
                        prop.style [ style.display.flex; style.gap 14; style.marginBottom 10; style.flexWrap.wrap ]
                        prop.children [
                            for (label, color) in legend ->
                                Html.div [
                                    prop.style [ style.display.flex; style.alignItems.center; style.gap 5; style.fontSize 12; style.color Theme.textMuted ]
                                    prop.children [
                                        Html.span [ prop.style [ style.width 10; style.height 10; style.borderRadius 5; style.backgroundColor color; style.display.inlineBlock ] ]
                                        Html.span [ prop.text label ]
                                    ]
                                ]
                        ]
                    ]
                    (match selected with
                     | None -> Html.div [ prop.style [ style.color Theme.textMuted; style.padding 20 ]; prop.text "Select an entity." ]
                     | Some _ -> remote graph "graph" (fun g ->
                                    if g.Nodes.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted; style.padding 20 ]; prop.text "No graph data in the recent window." ]
                                    else Charts.radialGraph g))
                ]
            ]
        ]
    ]
