module Astra.Client.Theme

/// Central palette + severity/status color helpers. A dark SOC console theme.
/// Colors are brand-neutral and original to Astra NDR.

let bg = "#0b0f1a"
let bgPanel = "#131a2b"
let bgPanelAlt = "#0f1524"
let border = "#22304d"
let textPrimary = "#e7edf7"
let textMuted = "#8a99b8"
let accent = "#4c8dff"
let accentDim = "#2b4d80"

let severityColor = function
    | "critical" -> "#ff4d6d"
    | "high" -> "#ff8c42"
    | "medium" -> "#ffd166"
    | "low" -> "#5bc0be"
    | _ -> "#6c7a94"

/// Map a 0-100 score to a threat color ramp.
let scoreColor (score: int) =
    if score >= 80 then "#ff4d6d"
    elif score >= 60 then "#ff8c42"
    elif score >= 40 then "#ffd166"
    elif score >= 20 then "#5bc0be"
    else "#6c7a94"

let statusColor = function
    | "online" -> "#3ddc97"
    | "degraded" -> "#ffd166"
    | "offline" -> "#ff4d6d"
    | "enrolling" -> "#4c8dff"
    | _ -> "#6c7a94"

let criticalityColor = function
    | "critical" -> "#ff4d6d"
    | "high" -> "#ff8c42"
    | "normal" -> "#5bc0be"
    | _ -> "#6c7a94"

/// Categorical palette for MITRE tactics / charts (colorblind-considerate).
let categorical =
    [| "#4c8dff"; "#3ddc97"; "#ffd166"; "#ff8c42"; "#ff4d6d"
       "#a78bfa"; "#5bc0be"; "#f78fb3"; "#8ecae6"; "#e0aaff"
       "#90be6d"; "#f9c74f"; "#f8961e"; "#577590" |]

let colorAt (i: int) = categorical.[i % categorical.Length]
