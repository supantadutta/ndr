module Astra.Client.App

open Feliz
open Browser.Dom
open Browser.Types
open Astra.Client
open Astra.Client.Types

/// Application shell: left navigation + hash-routed content area.

type private NavItem = { Route: Route; Label: string; Icon: string; Group: string }

let private navItems =
    [ { Route = Dashboard;             Label = "Dashboard";            Icon = "◧"; Group = "Operations" }
      { Route = Entities;              Label = "Entity Queue";         Icon = "⬢"; Group = "Operations" }
      { Route = DetectionsRoute;       Label = "Detections";           Icon = "◆"; Group = "Operations" }
      { Route = IncidentsRoute;        Label = "Incidents";            Icon = "✦"; Group = "Operations" }
      { Route = AttackGraph;           Label = "Attack Graph";         Icon = "⧉"; Group = "Investigation" }
      { Route = Hunting;               Label = "Threat Hunting";       Icon = "⌕"; Group = "Investigation" }
      { Route = Sensors;               Label = "Sensor Health";        Icon = "◉"; Group = "Fleet" }
      { Route = DetectionEngineering;  Label = "Detection Engineering";Icon = "⚙"; Group = "Engineering" }
      { Route = ThreatIntel;           Label = "Threat Intelligence";  Icon = "☰"; Group = "Engineering" }
      { Route = ResponseCenter;        Label = "Response Center";      Icon = "⛨"; Group = "Engineering" }
      { Route = Admin;                 Label = "Admin Settings";       Icon = "⚑"; Group = "Engineering" } ]

let private useHashRoute () =
    let (route, setRoute) = React.useState (Route.parse window.location.hash)
    React.useEffectOnce(fun () ->
        let handler = fun (_: Event) -> setRoute (Route.parse window.location.hash)
        window.addEventListener("hashchange", handler)
        { new System.IDisposable with
            member _.Dispose() = window.removeEventListener("hashchange", handler) })
    route

let private navLink (current: Route) (item: NavItem) =
    let isActive =
        match current, item.Route with
        | EntityDetailRoute _, Entities -> true
        | a, b -> a = b
    Html.a [
        prop.href (Route.toHash item.Route)
        prop.style [
            style.display.flex; style.alignItems.center; style.gap 10
            style.padding (9, 12); style.borderRadius 8
            style.textDecoration.none; style.fontSize 14
            style.color (if isActive then Theme.textPrimary else Theme.textMuted)
            style.backgroundColor (if isActive then Theme.accentDim else "transparent")
            style.borderLeft (3, borderStyle.solid, (if isActive then Theme.accent else "transparent"))
        ]
        prop.children [
            Html.span [ prop.style [ style.fontSize 15; style.width 18; style.textAlign.center ]; prop.text item.Icon ]
            Html.span [ prop.text item.Label ]
        ]
    ]

let private content (route: Route) =
    match route with
    | Dashboard -> Pages.Dashboard.Dashboard ()
    | Entities -> Pages.EntityQueue.EntityQueue ()
    | EntityDetailRoute id -> Pages.EntityDetail.EntityDetail id
    | DetectionsRoute -> Pages.Detections.Detections ()
    | IncidentsRoute -> Pages.Incidents.Incidents ()
    | Sensors -> Pages.Sensors.Sensors ()
    | AttackGraph -> Pages.AttackGraph.AttackGraph ()
    | Hunting -> Pages.Hunting.Hunting ()
    | DetectionEngineering -> Pages.DetectionEngineering.DetectionEngineering ()
    | ThreatIntel ->
        Pages.Placeholder.Placeholder "Threat Intelligence" "Phase 5"
            [ "IOC and feed management (IP / domain / URL / hash)"; "CSV / STIX-style import"
              "Indicator match history"; "Actor / tool / campaign context" ]
    | ResponseCenter ->
        Pages.Placeholder.Placeholder "Response Center" "Phase 5"
            [ "Analyst-approved response workflows"; "Blocklist feeds and connector status"
              "Simulation mode and audit trail"; "SIEM / SOAR / EDR / firewall connectors" ]
    | Admin -> Pages.Admin.Admin ()

[<ReactComponent>]
let App () =
    let route = useHashRoute ()
    Html.div [
        prop.style [ style.display.flex; style.minHeight (length.vh 100); style.backgroundColor Theme.bg; style.color Theme.textPrimary; style.fontFamily "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif" ]
        prop.children [
            // ---- sidebar ----
            Html.div [
                prop.style [
                    style.width 250; style.flexShrink 0
                    style.backgroundColor Theme.bgPanel
                    style.borderRight (1, borderStyle.solid, Theme.border)
                    style.padding 16; style.boxSizing.borderBox
                    style.position.sticky; style.top 0; style.height (length.vh 100)
                    style.overflowY.auto
                ]
                prop.children [
                    Html.div [
                        prop.style [ style.display.flex; style.alignItems.center; style.gap 10; style.marginBottom 24; style.padding (4, 8) ]
                        prop.children [
                            Html.div [ prop.style [ style.width 30; style.height 30; style.borderRadius 8; style.backgroundColor Theme.accent; style.display.flex; style.alignItems.center; style.justifyContent.center; style.fontWeight 700; style.color "#0b0f1a" ]; prop.text "A" ]
                            Html.div [
                                prop.children [
                                    Html.div [ prop.style [ style.fontWeight 700; style.fontSize 16 ]; prop.text "Astra NDR" ]
                                    Html.div [ prop.style [ style.fontSize 10; style.color Theme.textMuted ]; prop.text "Network Detection & Response" ]
                                ]
                            ]
                        ]
                    ]
                    for group in [ "Operations"; "Investigation"; "Fleet"; "Engineering" ] do
                        Html.div [
                            prop.style [ style.fontSize 10; style.textTransform.uppercase; style.letterSpacing 1; style.color Theme.textMuted; style.margin (14, 8, 6, 8); style.fontWeight 600 ]
                            prop.text group
                        ]
                        for item in navItems |> List.filter (fun n -> n.Group = group) do
                            navLink route item
                ]
            ]
            // ---- content ----
            Html.div [
                prop.style [ style.flexGrow 1; style.padding 24; style.boxSizing.borderBox; style.maxWidth 1500; style.margin (0, length.auto) ]
                prop.children [ content route ]
            ]
        ]
    ]
