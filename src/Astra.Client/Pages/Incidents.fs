module Astra.Client.Pages.Incidents

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let Incidents () =
    let (items, setItems) = React.useState<Result<IncidentListItem list, string> option> None
    React.useEffectOnce(fun () -> Api.getIncidents () |> Promise.map (Some >> setItems) |> Promise.start)

    Html.div [
        pageHeader "Incident Workbench" "Correlated attack campaigns raised from clustered detections"
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
