module Astra.Client.Charts

open Feliz
open Astra.Client.Types

/// Lightweight inline SVG charts — no external chart library, CSP-friendly.

/// Horizontal bar list, e.g. MITRE tactic distribution.
let horizontalBars (title: string) (data: (string * int * string) list) =
    let maxVal = data |> List.map (fun (_, v, _) -> v) |> function [] -> 1 | xs -> max 1 (List.max xs)
    Html.div [
        prop.children [
            Html.div [
                prop.style [ style.fontSize 13; style.color Theme.textMuted; style.marginBottom 12; style.fontWeight 600 ]
                prop.text title
            ]
            Html.div [
                prop.style [ style.display.flex; style.flexDirection.column; style.gap 10 ]
                prop.children [
                    for (label, value, color) in data ->
                        Html.div [
                            prop.children [
                                Html.div [
                                    prop.style [ style.display.flex; style.justifyContent.spaceBetween; style.fontSize 12; style.marginBottom 3 ]
                                    prop.children [
                                        Html.span [ prop.style [ style.color Theme.textPrimary ]; prop.text label ]
                                        Html.span [ prop.style [ style.color Theme.textMuted ]; prop.text (string value) ]
                                    ]
                                ]
                                Html.div [
                                    prop.style [ style.height 8; style.backgroundColor Theme.bgPanelAlt; style.borderRadius 4; style.overflow.hidden ]
                                    prop.children [
                                        Html.div [
                                            prop.style [
                                                style.height 8
                                                style.width (length.percent (float value / float maxVal * 100.0))
                                                style.backgroundColor color
                                                style.borderRadius 4
                                            ]
                                        ]
                                    ]
                                ]
                            ]
                        ]
                ]
            ]
        ]
    ]

/// Sparkline-style area/line for the detection trend.
let trendLine (title: string) (points: DetectionTrendPoint list) =
    let w, h = 520.0, 120.0
    let n = max 1 points.Length
    let maxVal = points |> List.map (fun p -> p.Count) |> function [] -> 1 | xs -> max 1 (List.max xs)
    let coords =
        points
        |> List.mapi (fun i p ->
            let x = if n = 1 then 0.0 else float i / float (n - 1) * w
            let y = h - (float p.Count / float maxVal * (h - 10.0)) - 5.0
            x, y)
    let linePath =
        coords
        |> List.mapi (fun i (x, y) -> sprintf "%s%.1f,%.1f" (if i = 0 then "M" else "L") x y)
        |> String.concat " "
    let areaPath =
        match coords with
        | [] -> ""
        | (x0, _) :: _ ->
            let (xn, _) = List.last coords
            sprintf "%s L%.1f,%.1f L%.1f,%.1f Z" linePath xn h x0 h

    Html.div [
        prop.children [
            Html.div [
                prop.style [ style.fontSize 13; style.color Theme.textMuted; style.marginBottom 12; style.fontWeight 600 ]
                prop.text title
            ]
            Svg.svg [
                svg.viewBox (0, 0, int w, int h)
                svg.custom ("width", "100%")
                svg.custom ("height", "120")
                svg.custom ("preserveAspectRatio", "none")
                svg.children [
                    yield Svg.path [ svg.d areaPath; svg.fill Theme.accentDim; svg.fillOpacity 0.25 ]
                    yield Svg.path [ svg.d linePath; svg.fill "none"; svg.stroke Theme.accent; svg.strokeWidth 2 ]
                    for (x, y) in coords do
                        yield Svg.circle [ svg.cx x; svg.cy y; svg.r 2.5; svg.fill Theme.accent ]
                ]
            ]
        ]
    ]

/// Radial investigation graph: a focal node in the centre with related nodes
/// arranged on a ring, edges drawn as lines. No physics engine — a clean
/// deterministic layout that reads well for attack-path investigation.
let radialGraph (graph: InvestigationGraph) =
    let w, h = 760.0, 460.0
    let cx, cy = w / 2.0, h / 2.0
    // focal node = the one with the most incident edges (host/incident centre)
    let degree (id: string) = graph.Edges |> List.filter (fun e -> e.FromNode = id || e.ToNode = id) |> List.length
    let focal =
        match graph.Nodes with
        | [] -> None
        | ns -> Some (ns |> List.maxBy (fun n -> degree n.NodeId))
    let others = graph.Nodes |> List.filter (fun n -> Some n.NodeId <> (focal |> Option.map (fun f -> f.NodeId)))
    let n = max 1 others.Length
    let radius = 170.0
    let pos =
        [ match focal with Some f -> yield f.NodeId, (cx, cy) | None -> ()
          for i, node in List.indexed others ->
            let angle = 2.0 * System.Math.PI * float i / float n - System.Math.PI / 2.0
            node.NodeId, (cx + radius * cos angle, cy + radius * sin angle) ]
        |> Map.ofList
    let kindColor = function
        | "host" -> "#4c8dff" | "ip" -> "#ff8c42" | "domain" -> "#a78bfa"
        | "detection" -> "#ff4d6d" | "incident" -> "#ffd166" | "account" -> "#3ddc97"
        | _ -> "#6c7a94"
    let nodeR (node: GraphNode) = if Some node.NodeId = (focal |> Option.map (fun f -> f.NodeId)) then 22.0 else 13.0

    Html.div [
        prop.style [ style.overflowX.auto ]
        prop.children [
            Svg.svg [
                svg.viewBox (0, 0, int w, int h)
                svg.custom ("width", "100%")
                svg.custom ("height", "460")
                svg.children [
                    // edges
                    for e in graph.Edges do
                        match Map.tryFind e.FromNode pos, Map.tryFind e.ToNode pos with
                        | Some (x1, y1), Some (x2, y2) ->
                            yield Svg.line [ svg.x1 x1; svg.y1 y1; svg.x2 x2; svg.y2 y2
                                             svg.stroke Theme.border; svg.strokeWidth (1.0 + min 3.0 e.Weight) ]
                        | _ -> ()
                    // nodes
                    for node in graph.Nodes do
                        match Map.tryFind node.NodeId pos with
                        | Some (x, y) ->
                            yield Svg.circle [ svg.cx x; svg.cy y; svg.r (nodeR node)
                                               svg.fill (kindColor node.Kind); svg.stroke Theme.bg; svg.strokeWidth 2 ]
                            yield Svg.text [ svg.x x; svg.y (y + nodeR node + 12.0); svg.textAnchor.middle
                                             svg.fill Theme.textPrimary; svg.fontSize 10
                                             svg.text (if node.Label.Length > 22 then node.Label.Substring(0, 20) + "…" else node.Label) ]
                        | None -> ()
                ]
            ]
        ]
    ]
