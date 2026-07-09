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
