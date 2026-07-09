module Astra.Client.Pages.Placeholder

open Feliz
open Astra.Client
open Astra.Client.Components

/// Roadmap placeholder for pages delivered in later phases. It states clearly
/// which phase implements the page so the console shows the full product map.

[<ReactComponent>]
let Placeholder (title: string) (phase: string) (capabilities: string list) =
    Html.div [
        pageHeader title (sprintf "Planned for %s" phase)
        panel [
            Html.div [ prop.style [ style.fontSize 13; style.color Theme.textMuted; style.marginBottom 12 ]
                       prop.text "This capability area is part of the Astra NDR architecture and is scheduled in the delivery roadmap. Planned features:" ]
            Html.ul [
                prop.style [ style.margin 0; style.paddingLeft 20; style.color Theme.textPrimary; style.fontSize 14; style.lineHeight 1.8 ]
                prop.children [ for c in capabilities -> Html.li [ prop.text c ] ]
            ]
        ]
    ]
