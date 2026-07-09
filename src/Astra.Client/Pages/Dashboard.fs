module Astra.Client.Pages.Dashboard

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

[<ReactComponent>]
let Dashboard () =
    let (summary, setSummary) = React.useState<Result<DashboardSummary, string> option> None
    let (sensors, setSensors) = React.useState<Result<SensorHealth list, string> option> None
    let (detections, setDetections) = React.useState<Result<DetectionPage, string> option> None
    let (entities, setEntities) = React.useState<Result<EntityQueuePage, string> option> None

    React.useEffectOnce(fun () ->
        Api.getDashboard () |> Promise.map (Some >> setSummary) |> Promise.start
        Api.getSensors () |> Promise.map (Some >> setSensors) |> Promise.start
        Api.getDetections 1 |> Promise.map (Some >> setDetections) |> Promise.start
        Api.getEntityQueue 1 |> Promise.map (Some >> setEntities) |> Promise.start)

    Html.div [
        pageHeader "Executive Dashboard" "Environment-wide detection, risk and sensor posture"

        // ---- stat tiles ----
        remote summary "dashboard" (fun s ->
            Html.div [
                prop.style [ style.display.flex; style.gap 14; style.flexWrap.wrap; style.marginBottom 18 ]
                prop.children [
                    statTile "Active incidents" (string s.ActiveIncidents) "#ff4d6d"
                    statTile "Open detections" (string s.OpenDetections) "#ff8c42"
                    statTile "Critical detections" (string s.CriticalDetections) "#ff4d6d"
                    statTile "Prioritized entities" (string s.PrioritizedEntities) "#4c8dff"
                    statTile "Sensors online" (sprintf "%d/%d" s.SensorsOnline s.SensorsTotal) "#3ddc97"
                    statTile "Events (24h)" (string s.EventsLast24h) "#5bc0be"
                ]
            ])

        // ---- charts row ----
        Html.div [
            prop.style [ style.display.grid; style.gridTemplateColumns [ length.fr 1; length.fr 1 ]; style.gap 14; style.marginBottom 18 ]
            prop.children [
                panel [
                    remote summary "tactics" (fun s ->
                        Charts.horizontalBars "MITRE ATT&CK tactic distribution"
                            (s.TacticDistribution |> List.mapi (fun i t -> t.Tactic, t.Count, Theme.colorAt i)))
                ]
                panel [
                    remote summary "trend" (fun s ->
                        Charts.trendLine "Detection trend (12h)" s.DetectionTrend)
                ]
            ]
        ]

        // ---- prioritized entities + critical detections ----
        Html.div [
            prop.style [ style.display.grid; style.gridTemplateColumns [ length.fr 1; length.fr 1 ]; style.gap 14; style.marginBottom 18 ]
            prop.children [
                panelTitled "Top prioritized entities" [
                    remote entities "entities" (fun page ->
                        if page.Items.IsEmpty then
                            Html.div [ prop.style [ style.color Theme.textMuted; style.fontSize 13 ]; prop.text "No prioritized entities yet." ]
                        else
                        table [ "Urgency"; "Entity"; "Type"; "Detections"; "Criticality" ] [
                            for e in page.Items |> List.truncate 6 ->
                                Html.tr [
                                    td [ scoreChip e.Urgency ]
                                    td [ Html.a [ prop.href (Route.toHash (EntityDetailRoute e.EntityId)); prop.style [ style.color Theme.accent; style.textDecoration.none ]; prop.text e.DisplayName ] ]
                                    tdText e.EntityType
                                    tdText (string e.DetectionCount)
                                    td [ badge e.Criticality (Theme.criticalityColor e.Criticality) ]
                                ]
                        ])
                ]
                panelTitled "Highest-threat detections" [
                    remote detections "detections" (fun page ->
                        if page.Items.IsEmpty then
                            Html.div [ prop.style [ style.color Theme.textMuted; style.fontSize 13 ]; prop.text "No detections yet." ]
                        else
                        table [ "Threat"; "Detection"; "Tactic"; "Severity" ] [
                            for d in page.Items |> List.truncate 6 ->
                                Html.tr [
                                    td [ scoreChip d.ThreatScore ]
                                    td [ Html.a [ prop.href (Route.toHash DetectionsRoute); prop.style [ style.color Theme.accent; style.textDecoration.none ]; prop.text d.Title ] ]
                                    tdText d.Tactic
                                    td [ severityBadge d.Severity ]
                                ]
                        ])
                ]
            ]
        ]

        // ---- sensor health summary ----
        panelTitled "Sensor health" [
            remote sensors "sensors" (fun list ->
                Html.div [
                    prop.style [ style.display.flex; style.gap 16; style.flexWrap.wrap ]
                    prop.children [
                        for sensor in list ->
                            Html.div [
                                prop.style [
                                    style.flexGrow 1; style.minWidth 220
                                    style.padding 14; style.borderRadius 8
                                    style.backgroundColor Theme.bgPanelAlt
                                    style.border (1, borderStyle.solid, Theme.border)
                                ]
                                prop.children [
                                    Html.div [
                                        prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.alignItems.center; style.marginBottom 8 ]
                                        prop.children [
                                            Html.span [ prop.style [ style.fontWeight 600; style.color Theme.textPrimary ]; prop.text sensor.Name ]
                                            badge sensor.Status (Theme.statusColor sensor.Status)
                                        ]
                                    ]
                                    Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text (sprintf "zone: %s · %s" sensor.Zone sensor.Mode) ]
                                    Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 6 ]; prop.text (sprintf "CPU %.0f%% · RAM %.0f%% · drop %.1f%%" sensor.CpuPercent sensor.MemoryPercent sensor.PacketDropPercent) ]
                                    Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 2 ]; prop.text (sprintf "%.0f eps" sensor.EventsPerSecond) ]
                                ]
                            ]
                    ]
                ])
        ]
    ]
