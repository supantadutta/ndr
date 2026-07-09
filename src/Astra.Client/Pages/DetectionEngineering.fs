module Astra.Client.Pages.DetectionEngineering

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let private RuleRow (rule: DetectionRule) (onChanged: DetectionRule -> unit) =
    let (busy, setBusy) = React.useState false
    let toggle () =
        setBusy true
        Api.updateRule rule.RuleId (Some (not rule.Enabled)) []
        |> Promise.map (fun r -> setBusy false; (match r with Ok x -> onChanged x | Error _ -> ()))
        |> Promise.start

    Html.tr [
        td [
            Html.button [
                prop.disabled busy
                prop.onClick (fun _ -> toggle ())
                prop.style [
                    style.padding (3, 10); style.borderRadius 6; style.fontSize 11; style.fontWeight 600
                    style.cursor.pointer; style.border (1, borderStyle.solid, (if rule.Enabled then "#3ddc97" else "#6c7a94"))
                    style.color (if rule.Enabled then "#3ddc97" else "#6c7a94")
                    style.backgroundColor "transparent"
                ]
                prop.text (if rule.Enabled then "ENABLED" else "DISABLED")
            ]
        ]
        td [ Html.div [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text rule.Name ]
             Html.div [ prop.style [ style.fontSize 11; style.color Theme.textMuted ]; prop.text rule.RuleId ] ]
        tdText (rule.Category.Replace("_", " "))
        td [ Html.span [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text (sprintf "%s %s" rule.TechniqueId rule.TechniqueName) ] ]
        td [ severityBadge rule.DefaultSeverity ]
        td [ Html.span [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]
                         prop.text (rule.Thresholds |> List.map (fun t -> sprintf "%s=%g" t.Key t.Value) |> String.concat ", ") ] ]
        td [ if rule.OpenDetections > 0 then scoreChip rule.OpenDetections else Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text "0" ] ]
    ]

[<ReactComponent>]
let DetectionEngineering () =
    let (rules, setRules) = React.useState<Result<DetectionRule list, string> option> None
    let load () = Api.getRules () |> Promise.map (Some >> setRules) |> Promise.start
    React.useEffectOnce(fun () -> load ())

    let onChanged (updated: DetectionRule) =
        match rules with
        | Some (Ok list) -> setRules (Some (Ok (list |> List.map (fun r -> if r.RuleId = updated.RuleId then updated else r))))
        | _ -> ()

    Html.div [
        pageHeader "Detection Engineering" "Enable, disable and tune detection rules — changes take effect on the next analysis cycle"
        panel [
            remote rules "rules" (fun list ->
                Html.div [
                    prop.children [
                        Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginBottom 12 ]
                                   prop.text (sprintf "%d rules · %d enabled · %d producing open detections"
                                                list.Length
                                                (list |> List.filter (fun r -> r.Enabled) |> List.length)
                                                (list |> List.filter (fun r -> r.OpenDetections > 0) |> List.length)) ]
                        table [ "Status"; "Rule"; "Category"; "Technique"; "Severity"; "Thresholds"; "Open" ]
                            [ for r in list |> List.sortBy (fun r -> r.Category, r.Name) -> RuleRow r onChanged ]
                    ]
                ])
        ]
    ]
