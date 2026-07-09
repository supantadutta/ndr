module Astra.Client.Pages.Sensors

open Feliz
open Astra.Client
open Astra.Client.Types
open Astra.Client.Components

let private healthBar (label: string) (pct: float) =
    let color = if pct >= 85.0 then "#ff4d6d" elif pct >= 65.0 then "#ffd166" else "#3ddc97"
    Html.div [
        prop.style [ style.marginBottom 6 ]
        prop.children [
            Html.div [ prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.fontSize 11; style.color Theme.textMuted; style.marginBottom 2 ]
                       prop.children [ Html.span [ prop.text label ]; Html.span [ prop.text (sprintf "%.0f%%" pct) ] ] ]
            Html.div [ prop.style [ style.height 6; style.backgroundColor Theme.bgPanelAlt; style.borderRadius 3; style.overflow.hidden ]
                       prop.children [ Html.div [ prop.style [ style.height 6; style.width (length.percent pct); style.backgroundColor color; style.borderRadius 3 ] ] ] ]
        ]
    ]

[<ReactComponent>]
let Sensors () =
    let (items, setItems) = React.useState<Result<SensorHealth list, string> option> None
    React.useEffectOnce(fun () -> Api.getSensors () |> Promise.map (Some >> setItems) |> Promise.start)

    Html.div [
        pageHeader "Sensor Health" "Fleet status, capture health and pipeline state"
        remote items "sensors" (fun list ->
            Html.div [
                prop.style [ style.display.grid; style.gridTemplateColumns [ length.fr 1; length.fr 1; length.fr 1 ]; style.gap 14 ]
                prop.children [
                    for s in list ->
                        panel [
                            Html.div [
                                prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.alignItems.center; style.marginBottom 12 ]
                                prop.children [
                                    Html.div [
                                        prop.children [
                                            Html.div [ prop.style [ style.fontWeight 700; style.color Theme.textPrimary; style.fontSize 15 ]; prop.text s.Name ]
                                            Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted ]; prop.text (sprintf "%s · v%s · %s" s.Zone s.Version s.Mode) ]
                                        ]
                                    ]
                                    badge s.Status (Theme.statusColor s.Status)
                                ]
                            ]
                            healthBar "CPU" s.CpuPercent
                            healthBar "Memory" s.MemoryPercent
                            healthBar "Disk" s.DiskPercent
                            Html.div [
                                prop.style [ style.display.flex; style.gap 12; style.marginTop 10; style.fontSize 12; style.color Theme.textMuted ]
                                prop.children [
                                    Html.span [ prop.text (sprintf "%.0f eps" s.EventsPerSecond) ]
                                    Html.span [ prop.text (sprintf "drop %.1f%%" s.PacketDropPercent) ]
                                ]
                            ]
                            Html.div [
                                prop.style [ style.display.flex; style.gap 8; style.marginTop 10 ]
                                prop.children [
                                    badge (if s.ZeekRunning then "zeek" else "zeek down") (if s.ZeekRunning then "#3ddc97" else "#ff4d6d")
                                    badge (if s.SuricataRunning then "suricata" else "suricata down") (if s.SuricataRunning then "#3ddc97" else "#ff4d6d")
                                    badge (if s.InterfaceUp then "iface up" else "iface down") (if s.InterfaceUp then "#3ddc97" else "#ff4d6d")
                                ]
                            ]
                            if not s.Errors.IsEmpty then
                                Html.div [
                                    prop.style [ style.marginTop 10; style.fontSize 12; style.color "#ffb3c1" ]
                                    prop.children [ for e in s.Errors -> Html.div [ prop.text (sprintf "⚠ %s" e) ] ]
                                ]
                        ]
                ]
            ])
    ]
