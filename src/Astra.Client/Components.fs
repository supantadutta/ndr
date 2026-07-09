module Astra.Client.Components

open Feliz
open Astra.Client.Types

/// Reusable UI primitives: panels, badges, stat tiles, loading/error states.

let panel (children: ReactElement list) =
    Html.div [
        prop.style [
            style.backgroundColor Theme.bgPanel
            style.border (1, borderStyle.solid, Theme.border)
            style.borderRadius 10
            style.padding 18
        ]
        prop.children children
    ]

let panelTitled (title: string) (children: ReactElement list) =
    panel [
        Html.div [
            prop.style [ style.fontSize 13; style.fontWeight 600; style.color Theme.textMuted; style.marginBottom 14; style.textTransform.uppercase; style.letterSpacing 1 ]
            prop.text title
        ]
        yield! children
    ]

let statTile (label: string) (value: string) (accent: string) =
    Html.div [
        prop.style [
            style.backgroundColor Theme.bgPanel
            style.border (1, borderStyle.solid, Theme.border)
            style.borderLeft (3, borderStyle.solid, accent)
            style.borderRadius 10
            style.padding 18
            style.flexGrow 1
            style.minWidth 150
        ]
        prop.children [
            Html.div [ prop.style [ style.fontSize 28; style.fontWeight 700; style.color Theme.textPrimary ]; prop.text value ]
            Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginTop 4 ]; prop.text label ]
        ]
    ]

let badge (text: string) (color: string) =
    Html.span [
        prop.style [
            style.display.inlineBlock
            style.padding (2, 8)
            style.borderRadius 6
            style.fontSize 11
            style.fontWeight 600
            style.color color
            style.border (1, borderStyle.solid, color)
            style.backgroundColor "transparent"
        ]
        prop.text (text.ToUpper())
    ]

let severityBadge (severity: string) = badge severity (Theme.severityColor severity)

let scoreChip (score: int) =
    Html.span [
        prop.style [
            style.display.inlineFlex
            style.alignItems.center
            style.justifyContent.center
            style.minWidth 34
            style.padding (2, 6)
            style.borderRadius 6
            style.fontSize 13
            style.fontWeight 700
            style.color "#0b0f1a"
            style.backgroundColor (Theme.scoreColor score)
        ]
        prop.text (string score)
    ]

let loading (label: string) =
    Html.div [
        prop.style [ style.padding 40; style.textAlign.center; style.color Theme.textMuted ]
        prop.text (sprintf "Loading %s…" label)
    ]

let errorBox (msg: string) =
    Html.div [
        prop.style [
            style.padding 16; style.borderRadius 8
            style.backgroundColor "#2a1220"; style.border (1, borderStyle.solid, "#ff4d6d")
            style.color "#ffb3c1"
        ]
        prop.text (sprintf "Failed to load: %s" msg)
    ]

/// Render a remote-data view: loading / error / success.
let remote (state: Result<'T, string> option) (label: string) (render: 'T -> ReactElement) =
    match state with
    | None -> loading label
    | Some (Error e) -> errorBox e
    | Some (Ok data) -> render data

let pageHeader (title: string) (subtitle: string) =
    Html.div [
        prop.style [ style.marginBottom 20 ]
        prop.children [
            Html.h1 [ prop.style [ style.fontSize 22; style.fontWeight 700; style.color Theme.textPrimary; style.margin 0 ]; prop.text title ]
            Html.div [ prop.style [ style.fontSize 13; style.color Theme.textMuted; style.marginTop 4 ]; prop.text subtitle ]
        ]
    ]

/// Simple table helper.
let table (headers: string list) (rows: ReactElement list) =
    Html.div [
        prop.style [ style.overflowX.auto ]
        prop.children [
            Html.table [
                prop.style [ style.width (length.percent 100); style.borderCollapse.collapse; style.fontSize 13 ]
                prop.children [
                    Html.thead [
                        Html.tr [
                            for h in headers ->
                                Html.th [
                                    prop.style [
                                        style.textAlign.left; style.padding (10, 12)
                                        style.color Theme.textMuted; style.fontSize 11
                                        style.fontWeight 600; style.textTransform.uppercase
                                        style.borderBottom (1, borderStyle.solid, Theme.border)
                                        style.custom ("whiteSpace", "nowrap")
                                    ]
                                    prop.text h
                                ]
                        ]
                    ]
                    Html.tbody rows
                ]
            ]
        ]
    ]

let td (children: ReactElement list) =
    Html.td [
        prop.style [ style.padding (10, 12); style.borderBottom (1, borderStyle.solid, Theme.bgPanelAlt); style.color Theme.textPrimary ]
        prop.children children
    ]

let tdText (text: string) = td [ Html.text text ]
