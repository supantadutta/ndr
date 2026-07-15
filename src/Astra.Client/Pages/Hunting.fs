module Astra.Client.Pages.Hunting

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Threat hunting: run canned templates or a custom field predicate over the
/// normalized-event window, with a results table and top-talker aggregations.

let private fields = [ "src_ip"; "dst_ip"; "domain"; "sni"; "user_agent"; "account"; "port"; "protocol"; "app"; "category"; "direction" ]
let private ops = [ "eq"; "contains"; "gt"; "lt" ]

[<ReactComponent>]
let Hunting () =
    let (templates, setTemplates) = React.useState<Result<HuntTemplate list, string> option> None
    let (result, setResult) = React.useState<Result<HuntResult, string> option> None
    let (field, setField) = React.useState "category"
    let (op, setOp) = React.useState "eq"
    let (value, setValue) = React.useState "dns"
    let (running, setRunning) = React.useState false

    React.useEffectOnce(fun () -> Api.getHuntTemplates () |> Promise.map (Some >> setTemplates) |> Promise.start)

    let run (q: HuntQuery) =
        setRunning true
        setResult None
        Api.runHunt q |> Promise.map (fun r -> setResult (Some r); setRunning false) |> Promise.start

    let runCustom () =
        run { Predicates = [ { Field = field; Op = op; Value = value } ]; WindowMinutes = 120; Limit = 200 }

    Html.div [
        pageHeader "Threat Hunting" "Query the normalized-event window; pivot on any field"

        // query builder
        panelTitled "Query" [
            Html.div [
                prop.style [ style.display.flex; style.gap 8; style.flexWrap.wrap; style.alignItems.center ]
                prop.children [
                    Html.select [
                        prop.value field
                        prop.onChange (fun (v: string) -> setField v)
                        prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6 ]
                        prop.children [ for f in fields -> Html.option [ prop.value f; prop.text f ] ]
                    ]
                    Html.select [
                        prop.value op
                        prop.onChange (fun (v: string) -> setOp v)
                        prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6 ]
                        prop.children [ for o in ops -> Html.option [ prop.value o; prop.text o ] ]
                    ]
                    Html.input [
                        prop.value value
                        prop.onChange (fun (v: string) -> setValue v)
                        prop.placeholder "value"
                        prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6; style.minWidth 200 ]
                    ]
                    Html.button [
                        prop.onClick (fun _ -> runCustom ())
                        prop.disabled running
                        prop.style [ style.padding (8, 16); style.backgroundColor Theme.accent; style.color "#0b0f1a"; style.border (0, borderStyle.none, ""); style.borderRadius 6; style.fontWeight 600; style.cursor.pointer ]
                        prop.text (if running then "Running…" else "Run hunt")
                    ]
                ]
            ]
            Html.div [
                prop.style [ style.marginTop 12; style.display.flex; style.gap 8; style.flexWrap.wrap ]
                prop.children [
                    remote templates "templates" (fun ts ->
                        Html.div [
                            prop.style [ style.display.flex; style.gap 8; style.flexWrap.wrap ]
                            prop.children [
                                for t in ts ->
                                    Html.button [
                                        prop.onClick (fun _ -> run t.Query)
                                        prop.title t.Description
                                        prop.style [ style.padding (6, 12); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6; style.fontSize 12; style.cursor.pointer ]
                                        prop.text t.Name
                                    ]
                            ]
                        ])
                ]
            ]
        ]

        // results
        Html.div [
            prop.style [ style.marginTop 14; style.display.grid; style.gridTemplateColumns [ length.fr 3; length.fr 1 ]; style.gap 14 ]
            prop.children [
                panelTitled "Results" [
                    match result with
                    | None -> Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "Run a hunt to see results." ]
                    | Some (Error e) -> errorBox e
                    | Some (Ok r) ->
                        Html.div [
                            prop.children [
                                Html.div [ prop.style [ style.fontSize 13; style.color Theme.textMuted; style.marginBottom 8 ]; prop.text (sprintf "%d matching events (showing %d)" r.Total r.Rows.Length) ]
                                if r.Rows.IsEmpty then Html.none
                                else
                                table [ "Time"; "Category"; "Proto"; "Source"; "Destination"; "Port"; "Detail" ] [
                                    for row in r.Rows |> List.truncate 100 ->
                                        Html.tr [
                                            tdText (row.Timestamp.Substring(11, 8))
                                            tdText row.Category
                                            tdText (sprintf "%s/%s" row.Protocol row.App)
                                            tdText row.SourceIp
                                            tdText row.DestinationIp
                                            tdText (row.DestinationPort |> Option.map string |> Option.defaultValue "-")
                                            td [ Html.span [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text row.Detail ] ]
                                        ]
                                ]
                            ]
                        ]
                ]
                panelTitled "Top talkers" [
                    match result with
                    | Some (Ok r) ->
                        Html.div [
                            prop.children [
                                Html.div [ prop.style [ style.fontSize 11; style.textTransform.uppercase; style.color Theme.textMuted; style.marginBottom 6 ]; prop.text "Destinations" ]
                                Charts.horizontalBars "" (r.TopDestinations |> List.mapi (fun i b -> b.Key, b.Count, Theme.colorAt i))
                                Html.div [ prop.style [ style.fontSize 11; style.textTransform.uppercase; style.color Theme.textMuted; style.margin (14, 0, 6, 0) ]; prop.text "Sources" ]
                                Charts.horizontalBars "" (r.TopSources |> List.mapi (fun i b -> b.Key, b.Count, Theme.colorAt i))
                            ]
                        ]
                    | _ -> Html.div [ prop.style [ style.color Theme.textMuted; style.fontSize 13 ]; prop.text "—" ]
                ]
            ]
        ]
    ]
