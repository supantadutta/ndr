module Astra.Client.Pages.EntityDetail

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let private AssistantPanel (entityId: string) =
    let (summary, setSummary) = React.useState<Result<AssistantSummary, string> option> None
    React.useEffect((fun () -> Api.getAssistantEntity entityId |> Promise.map (Some >> setSummary) |> Promise.start), [| box entityId |])

    let statements (title: string) (color: string) (items: AssistantStatement list) =
        if items.IsEmpty then Html.none
        else
        Html.div [
            prop.style [ style.marginBottom 12 ]
            prop.children [
                Html.div [ prop.style [ style.fontSize 11; style.fontWeight 600; style.textTransform.uppercase; style.color color; style.marginBottom 6 ]; prop.text title ]
                Html.div [
                    prop.style [ style.display.flex; style.flexDirection.column; style.gap 6 ]
                    prop.children [
                        for s in items ->
                            Html.div [
                                prop.style [ style.fontSize 13; style.color Theme.textPrimary; style.borderLeft (2, borderStyle.solid, color); style.paddingLeft 10 ]
                                prop.children [
                                    Html.span [ prop.text s.Text ]
                                    if not s.Citations.IsEmpty then
                                        Html.span [ prop.style [ style.fontSize 11; style.color Theme.textMuted; style.marginLeft 6 ]; prop.text (sprintf "[%d cited]" s.Citations.Length) ]
                                ]
                            ]
                    ]
                ]
            ]
        ]

    panelTitled "AI investigation summary" [
        remote summary "assistant" (fun a ->
            Html.div [
                prop.children [
                    Html.div [ prop.style [ style.fontSize 14; style.fontWeight 600; style.color Theme.textPrimary; style.marginBottom 4 ]; prop.text a.Headline ]
                    Html.div [ prop.style [ style.fontSize 11; style.color Theme.textMuted; style.marginBottom 12 ]; prop.text (sprintf "provider: %s · confidence %d%% · read-only, evidence-bound" a.Provider a.Confidence) ]
                    statements "Facts (observed)" "#5bc0be" a.Facts
                    statements "Inferences" "#ffd166" a.Inferences
                    statements "Recommendations" "#4c8dff" a.Recommendations
                    if not a.MitreTechniques.IsEmpty then
                        Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 8 ]; prop.text (sprintf "ATT&CK: %s" (String.concat ", " a.MitreTechniques)) ]
                    Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 8; style.fontStyle.italic ]; prop.text (sprintf "Uncertainty: %s" a.Uncertainty) ]
                ]
            ])
    ]

[<ReactComponent>]
let EntityDetail (entityId: string) =
    let (detail, setDetail) = React.useState<Result<EntityDetail, string> option> None
    React.useEffect((fun () -> Api.getEntityDetail entityId |> Promise.map (Some >> setDetail) |> Promise.start), [| box entityId |])

    Html.div [
        remote detail "entity" (fun e ->
            Html.div [
                prop.children [
                    pageHeader e.DisplayName (sprintf "%s · %s · first seen %s" e.EntityType (e.Criticality.ToUpper()) e.FirstSeen)

                    // score tiles
                    Html.div [
                        prop.style [ style.display.flex; style.gap 14; style.flexWrap.wrap; style.marginBottom 18 ]
                        prop.children [
                            statTile "Urgency" (string e.Urgency) (Theme.scoreColor e.Urgency)
                            statTile "Risk" (string e.Risk) (Theme.scoreColor e.Risk)
                            statTile "Threat" (string e.Threat) (Theme.scoreColor e.Threat)
                            statTile "Certainty" (string e.Certainty) (Theme.scoreColor e.Certainty)
                        ]
                    ]

                    Html.div [
                        prop.style [ style.display.grid; style.gridTemplateColumns [ length.fr 3; length.fr 2 ]; style.gap 14 ]
                        prop.children [
                            // score explanation
                            panelTitled "Why this score" [
                                if e.ScoreFactors.IsEmpty then
                                    Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No scoring factors recorded." ]
                                else
                                Html.div [
                                    prop.style [ style.display.flex; style.flexDirection.column; style.gap 10 ]
                                    prop.children [
                                        for f in e.ScoreFactors ->
                                            Html.div [
                                                prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.alignItems.flexStart; style.gap 12; style.paddingBottom 8; style.borderBottom (1, borderStyle.solid, Theme.bgPanelAlt) ]
                                                prop.children [
                                                    Html.div [
                                                        prop.children [
                                                            Html.div [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary; style.fontSize 13 ]; prop.text f.Label ]
                                                            Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 2 ]; prop.text f.Explanation ]
                                                        ]
                                                    ]
                                                    Html.span [
                                                        prop.style [
                                                            style.fontWeight 700; style.fontSize 14
                                                            style.color (if f.Contribution >= 0.0 then "#ff8c42" else "#3ddc97")
                                                            style.custom ("whiteSpace", "nowrap")
                                                        ]
                                                        prop.text (sprintf "%s%.1f" (if f.Contribution >= 0.0 then "+" else "") f.Contribution)
                                                    ]
                                                ]
                                            ]
                                    ]
                                ]
                            ]
                            // metadata
                            panelTitled "Entity" [
                                Html.div [
                                    prop.style [ style.display.flex; style.flexDirection.column; style.gap 8; style.fontSize 13 ]
                                    prop.children [
                                        Html.div [ prop.children [ Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "Canonical: " ]; Html.text e.CanonicalName ] ]
                                        Html.div [ prop.children [ Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "Last seen: " ]; Html.text e.LastSeen ] ]
                                        Html.div [ prop.children [ Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "Triage: " ]; Html.text (e.TriageState.Replace("_", " ")) ] ]
                                        Html.div [ prop.children [ Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "Related detections: " ]; Html.text (string e.RecentDetectionIds.Length) ] ]
                                        if not e.Tags.IsEmpty then
                                            Html.div [ prop.children [ Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "Tags: " ]; Html.text (String.concat ", " e.Tags) ] ]
                                    ]
                                ]
                            ]
                        ]
                    ]

                    // AI investigation summary (full width)
                    Html.div [
                        prop.style [ style.marginTop 14 ]
                        prop.children [ AssistantPanel e.EntityId ]
                    ]
                ]
            ])
    ]
