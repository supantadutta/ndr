module Astra.Client.Pages.ThreatIntel

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

/// Threat Intelligence: IOC list, add-indicator form, feeds, and match history.

[<ReactComponent>]
let ThreatIntel () =
    let indicators, updatedAt, refreshInd = useLiveData Api.getIndicators 15000
    let feeds, _, refreshFeeds = useLiveData Api.getFeeds 15000
    let matches, _, refreshMatches = useLiveData Api.getThreatMatches 10000
    let (indVal, setIndVal) = React.useState ""
    let (indType, setIndType) = React.useState "ip"
    let (indConf, setIndConf) = React.useState "75"
    let refreshAll () = refreshInd (); refreshFeeds (); refreshMatches ()

    let add () =
        if indVal.Trim() <> "" then
            let conf = match System.Int32.TryParse indConf with | true, n -> n | _ -> 75
            Api.addIndicator (indVal.Trim()) indType "analyst" conf "" "analyst"
            |> Promise.map (fun _ -> setIndVal ""; refreshAll ()) |> Promise.start

    Html.div [
        pageHeaderLive "Threat Intelligence" "Indicators, feeds, and match history" updatedAt refreshAll

        // add indicator
        panelTitled "Add indicator" [
            Html.div [
                prop.style [ style.display.flex; style.gap 8; style.flexWrap.wrap; style.alignItems.center ]
                prop.children [
                    Html.input [ prop.value indVal; prop.onChange (fun (v: string) -> setIndVal v); prop.placeholder "IP / domain / url / hash"
                                 prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6; style.minWidth 240 ] ]
                    Html.select [ prop.value indType; prop.onChange (fun (v: string) -> setIndType v)
                                  prop.style [ style.padding (7, 8); style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6 ]
                                  prop.children [ for t in [ "ip"; "domain"; "url"; "hash" ] -> Html.option [ prop.value t; prop.text t ] ] ]
                    Html.input [ prop.value indConf; prop.onChange (fun (v: string) -> setIndConf v); prop.placeholder "confidence"
                                 prop.style [ style.padding (7, 8); style.width 90; style.backgroundColor Theme.bgPanelAlt; style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border); style.borderRadius 6 ] ]
                    Html.button [ prop.onClick (fun _ -> add ())
                                  prop.style [ style.padding (8, 16); style.backgroundColor Theme.accent; style.color "#0b0f1a"; style.border (0, borderStyle.none, ""); style.borderRadius 6; style.fontWeight 600; style.cursor.pointer ]
                                  prop.text "Add indicator" ]
                ]
            ]
        ]

        Html.div [
            prop.style [ style.marginTop 14; style.display.grid; style.gridTemplateColumns [ length.fr 2; length.fr 1 ]; style.gap 14 ]
            prop.children [
                panelTitled "Indicators" [
                    remote indicators "indicators" (fun list ->
                        if list.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No indicators." ]
                        else
                        table [ "Indicator"; "Type"; "Feed"; "Actor"; "Confidence" ] [
                            for i in list ->
                                Html.tr [
                                    td [ Html.span [ prop.style [ style.fontFamily "monospace"; style.color Theme.textPrimary ]; prop.text i.Indicator ] ]
                                    tdText i.IndicatorType
                                    tdText i.FeedName
                                    tdText (defaultArg i.Actor "—")
                                    td [ scoreChip i.Confidence ]
                                ]
                        ])
                ]
                panelTitled "Feeds" [
                    remote feeds "feeds" (fun list ->
                        Html.div [
                            prop.style [ style.display.flex; style.flexDirection.column; style.gap 8 ]
                            prop.children [
                                for f in list ->
                                    Html.div [
                                        prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.padding 10; style.backgroundColor Theme.bgPanelAlt; style.borderRadius 6 ]
                                        prop.children [
                                            Html.div [ prop.children [ Html.div [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text f.Name ]; Html.div [ prop.style [ style.fontSize 11; style.color Theme.textMuted ]; prop.text f.Kind ] ] ]
                                            badge (sprintf "%d IOCs" f.IndicatorCount) Theme.accent
                                        ]
                                    ]
                            ]
                        ])
                ]
            ]
        ]

        Html.div [
            prop.style [ style.marginTop 14 ]
            prop.children [
                panelTitled "Match history" [
                    remote matches "matches" (fun list ->
                        if list.IsEmpty then Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No indicator matches observed." ]
                        else
                        table [ "Matched at"; "Indicator"; "Type"; "Feed"; "Actor"; "Value" ] [
                            for m in list ->
                                Html.tr [
                                    tdText (m.MatchedAt.Substring(0, 19).Replace("T", " "))
                                    td [ Html.span [ prop.style [ style.fontFamily "monospace"; style.color "#ff4d6d" ]; prop.text m.Indicator ] ]
                                    tdText m.IndicatorType
                                    tdText m.FeedName
                                    td [ (match m.Actor with Some a -> badge a "#ff8c42" | None -> Html.text "—") ]
                                    tdText m.MatchedValue
                                ]
                        ])
                ]
            ]
        ]
    ]
