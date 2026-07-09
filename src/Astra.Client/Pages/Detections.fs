module Astra.Client.Pages.Detections

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let Detections () =
    let page, updatedAt, refresh = useLiveData (fun () -> Api.getDetections 1) 10000
    let (selected, setSelected) = React.useState<Result<DetectionDetail, string> option> None
    let (selectedId, setSelectedId) = React.useState<string option> None

    let openDetail id =
        setSelectedId (Some id)
        setSelected None
        Api.getDetectionDetail id |> Promise.map (Some >> setSelected) |> Promise.start

    Html.div [
        pageHeaderLive "Detection Center" "Triage queue ordered by threat score" updatedAt refresh
        Html.div [
            prop.style [ style.display.grid; style.gridTemplateColumns [ length.fr 3; length.fr 2 ]; style.gap 14 ]
            prop.children [
                panel [
                    remote page "detections" (fun p ->
                        if p.Items.IsEmpty then
                            Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No detections." ]
                        else
                        table [ "Threat"; "Detection"; "Category"; "Technique"; "Severity"; "Conf" ] [
                            for d in p.Items ->
                                Html.tr [
                                    prop.style [ style.cursor.pointer; if selectedId = Some d.DetectionId then style.backgroundColor Theme.bgPanelAlt ]
                                    prop.onClick (fun _ -> openDetail d.DetectionId)
                                    prop.children [
                                        td [ scoreChip d.ThreatScore ]
                                        td [ Html.span [ prop.style [ style.color Theme.textPrimary; style.fontWeight 600 ]; prop.text d.Title ] ]
                                        tdText (d.Category.Replace("_", " "))
                                        td [ Html.span [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text (sprintf "%s %s" d.TechniqueId d.TechniqueName) ] ]
                                        td [ severityBadge d.Severity ]
                                        tdText (string d.Confidence)
                                    ]
                                ]
                        ])
                ]
                // detail pane
                panel [
                    match selectedId with
                    | None -> Html.div [ prop.style [ style.color Theme.textMuted; style.padding 20; style.textAlign.center ]; prop.text "Select a detection to view evidence and recommendations." ]
                    | Some _ ->
                        remote selected "detection" (fun d ->
                            Html.div [
                                prop.style [ style.display.flex; style.flexDirection.column; style.gap 14 ]
                                prop.children [
                                    Html.div [
                                        prop.children [
                                            Html.div [ prop.style [ style.display.flex; style.gap 8; style.marginBottom 8 ]; prop.children [ severityBadge d.Severity; badge d.Tactic Theme.accent ] ]
                                            Html.h2 [ prop.style [ style.fontSize 17; style.color Theme.textPrimary; style.margin 0 ]; prop.text d.Title ]
                                            Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 4 ]; prop.text (sprintf "%s · %s %s" d.EngineKind d.TechniqueId d.TechniqueName) ]
                                        ]
                                    ]
                                    Html.div [ prop.style [ style.fontSize 13; style.color Theme.textPrimary ]; prop.text d.Summary ]

                                    // ---- triage actions ----
                                    Html.div [
                                        prop.children [
                                            Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.color Theme.textMuted; style.textTransform.uppercase; style.marginBottom 6 ]; prop.text (sprintf "Triage — current: %s" (d.TriageState.Replace("_", " "))) ]
                                            Html.div [
                                                prop.style [ style.display.flex; style.gap 8; style.flexWrap.wrap ]
                                                prop.children [
                                                    let act (label: string) (action: string) (color: string) =
                                                        Html.button [
                                                            prop.onClick (fun _ ->
                                                                Api.triageDetection d.DetectionId action "analyst" None
                                                                |> Promise.map (fun r -> match r with Ok x -> setSelected (Some (Ok x)); refresh () | Error _ -> ())
                                                                |> Promise.start)
                                                            prop.style [
                                                                style.padding (5, 12); style.borderRadius 6; style.fontSize 12; style.cursor.pointer
                                                                style.border (1, borderStyle.solid, color); style.color color; style.backgroundColor "transparent"
                                                            ]
                                                            prop.text label
                                                        ]
                                                    act "Close benign" "close_benign" "#3ddc97"
                                                    act "Mark expected" "expected" "#5bc0be"
                                                    act "Escalate" "escalate" "#ff8c42"
                                                    act "Reopen" "reopen" "#6c7a94"
                                                ]
                                            ]
                                        ]
                                    ]

                                    Html.div [
                                        prop.children [
                                            Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.color Theme.textMuted; style.textTransform.uppercase; style.marginBottom 6 ]; prop.text "Why suspicious" ]
                                            Html.div [ prop.style [ style.fontSize 13; style.color Theme.textPrimary ]; prop.text d.WhySuspicious ]
                                        ]
                                    ]

                                    if not d.Evidence.IsEmpty then
                                        Html.div [
                                            prop.children [
                                                Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.color Theme.textMuted; style.textTransform.uppercase; style.marginBottom 6 ]; prop.text "Evidence" ]
                                                Html.div [
                                                    prop.style [ style.display.flex; style.flexDirection.column; style.gap 6 ]
                                                    prop.children [
                                                        for ev in d.Evidence ->
                                                            Html.div [
                                                                prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.fontSize 13; style.gap 12 ]
                                                                prop.children [
                                                                    Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text ev.Label ]
                                                                    Html.span [ prop.style [ style.color Theme.textPrimary; style.fontWeight 600; style.textAlign.right ]; prop.text ev.Value ]
                                                                ]
                                                            ]
                                                    ]
                                                ]
                                            ]
                                        ]

                                    if not d.RecommendedInvestigationSteps.IsEmpty then
                                        Html.div [
                                            prop.children [
                                                Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.color Theme.textMuted; style.textTransform.uppercase; style.marginBottom 6 ]; prop.text "Recommended investigation" ]
                                                Html.ul [
                                                    prop.style [ style.margin 0; style.paddingLeft 18; style.fontSize 13; style.color Theme.textPrimary ]
                                                    prop.children [ for step in d.RecommendedInvestigationSteps -> Html.li [ prop.style [ style.marginBottom 3 ]; prop.text step ] ]
                                                ]
                                            ]
                                        ]

                                    if not d.FalsePositiveConsiderations.IsEmpty then
                                        Html.div [
                                            prop.children [
                                                Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.color Theme.textMuted; style.textTransform.uppercase; style.marginBottom 6 ]; prop.text "False-positive considerations" ]
                                                Html.ul [
                                                    prop.style [ style.margin 0; style.paddingLeft 18; style.fontSize 12; style.color Theme.textMuted ]
                                                    prop.children [ for fp in d.FalsePositiveConsiderations -> Html.li [ prop.text fp ] ]
                                                ]
                                            ]
                                        ]
                                ]
                            ])
                ]
            ]
        ]
    ]
