module Astra.Client.Pages.EntityQueue

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let EntityQueue () =
    let page, updatedAt, refresh = useLiveData (fun () -> Api.getEntityQueue 1) 10000

    Html.div [
        pageHeaderLive "Prioritized Entity Queue" "Entities ranked by unified urgency score" updatedAt refresh
        panel [
            remote page "entities" (fun p ->
                if p.Items.IsEmpty then
                    Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No entities have accrued urgency yet." ]
                else
                table [ "Urgency"; "Risk"; "Threat"; "Certainty"; "Entity"; "Type"; "Detections"; "Incidents"; "Criticality"; "Triage" ] [
                    for e in p.Items ->
                        Html.tr [
                            td [ scoreChip e.Urgency ]
                            td [ scoreChip e.Risk ]
                            td [ scoreChip e.Threat ]
                            td [ scoreChip e.Certainty ]
                            td [ Html.a [ prop.href (Route.toHash (EntityDetailRoute e.EntityId)); prop.style [ style.color Theme.accent; style.textDecoration.none; style.fontWeight 600 ]; prop.text e.DisplayName ] ]
                            tdText e.EntityType
                            tdText (string e.DetectionCount)
                            tdText (string e.IncidentCount)
                            td [ badge e.Criticality (Theme.criticalityColor e.Criticality) ]
                            tdText (e.TriageState.Replace("_", " "))
                        ]
                ])
        ]
    ]
