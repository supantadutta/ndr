module Astra.Client.Pages.Incidents

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let Incidents () =
    let items, updatedAt, refresh = useLiveData Api.getIncidents 10000

    Html.div [
        pageHeaderLive "Incident Workbench" "Correlated attack campaigns raised from clustered detections" updatedAt refresh
        panel [
            remote items "incidents" (fun list ->
                if list.IsEmpty then
                    Html.div [ prop.style [ style.color Theme.textMuted ]; prop.text "No incidents raised." ]
                else
                table [ "Urgency"; "Incident"; "Attack profile"; "Primary entity"; "Detections"; "Blast radius"; "Severity"; "Status" ] [
                    for i in list ->
                        Html.tr [
                            td [ scoreChip i.Urgency ]
                            td [ Html.span [ prop.style [ style.color Theme.textPrimary; style.fontWeight 600 ]; prop.text i.Title ] ]
                            td [ badge (i.AttackProfile) Theme.accent ]
                            tdText i.PrimaryEntityName
                            tdText (string i.DetectionCount)
                            tdText (string i.AffectedEntityCount)
                            td [ severityBadge i.Severity ]
                            tdText i.Status
                        ]
                ])
        ]
    ]
