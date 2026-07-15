module Astra.Client.Pages.Login

open Feliz
open Astra.Client

/// Sign-in screen, shown only when the server reports ASTRA_AUTH_ENABLED=true
/// and no session token is held. On success the token is persisted and every
/// subsequent API call carries it as a bearer header.

[<ReactComponent>]
let Login (onSignedIn: unit -> unit) =
    let (username, setUsername) = React.useState ""
    let (password, setPassword) = React.useState ""
    let (error, setError) = React.useState<string option> None
    let (busy, setBusy) = React.useState false

    let submit () =
        if not busy && username.Trim() <> "" && password <> "" then
            setBusy true
            setError None
            Api.login (username.Trim()) password
            |> Promise.map (fun result ->
                setBusy false
                match result with
                | Ok r ->
                    Api.setToken (Some r.Token)
                    onSignedIn ()
                | Error _ -> setError (Some "Sign-in failed. Check your username and password."))
            |> Promise.start

    let field (label: string) (value: string) (isPassword: bool) (onChange: string -> unit) =
        Html.div [
            prop.style [ style.marginBottom 14 ]
            prop.children [
                Html.div [ prop.style [ style.fontSize 12; style.color Theme.textMuted; style.marginBottom 6 ]; prop.text label ]
                Html.input [
                    prop.value value
                    prop.onChange onChange
                    prop.type' (if isPassword then "password" else "text")
                    prop.onKeyDown (fun e -> if e.key = "Enter" then submit ())
                    prop.style [
                        style.width (length.percent 100); style.boxSizing.borderBox
                        style.padding (10, 12); style.backgroundColor Theme.bgPanelAlt
                        style.color Theme.textPrimary; style.border (1, borderStyle.solid, Theme.border)
                        style.borderRadius 8; style.fontSize 14
                    ]
                ]
            ]
        ]

    Html.div [
        prop.style [
            style.display.flex; style.alignItems.center; style.justifyContent.center
            style.minHeight (length.vh 100); style.backgroundColor Theme.bg
            style.fontFamily "Inter, system-ui, -apple-system, Segoe UI, Roboto, sans-serif"
        ]
        prop.children [
            Html.div [
                prop.style [
                    style.width 380; style.padding 32
                    style.backgroundColor Theme.bgPanel; style.borderRadius 12
                    style.border (1, borderStyle.solid, Theme.border)
                ]
                prop.children [
                    Html.div [
                        prop.style [ style.display.flex; style.alignItems.center; style.gap 10; style.marginBottom 24 ]
                        prop.children [
                            Html.div [ prop.style [ style.width 34; style.height 34; style.borderRadius 8; style.backgroundColor Theme.accent; style.display.flex; style.alignItems.center; style.justifyContent.center; style.fontWeight 700; style.color "#0b0f1a" ]; prop.text "A" ]
                            Html.div [
                                prop.children [
                                    Html.div [ prop.style [ style.fontWeight 700; style.fontSize 18; style.color Theme.textPrimary ]; prop.text "Astra NDR" ]
                                    Html.div [ prop.style [ style.fontSize 11; style.color Theme.textMuted ]; prop.text "Analyst console sign-in" ]
                                ]
                            ]
                        ]
                    ]
                    field "Username" username false setUsername
                    field "Password" password true setPassword
                    (match error with
                     | Some e ->
                        Html.div [ prop.style [ style.padding 10; style.marginBottom 12; style.borderRadius 8
                                                style.backgroundColor "#2a1220"; style.border (1, borderStyle.solid, "#ff4d6d")
                                                style.color "#ffb3c1"; style.fontSize 13 ]
                                   prop.text e ]
                     | None -> Html.none)
                    Html.button [
                        prop.onClick (fun _ -> submit ())
                        prop.disabled busy
                        prop.style [
                            style.width (length.percent 100); style.padding (11, 0)
                            style.backgroundColor Theme.accent; style.color "#0b0f1a"
                            style.border (0, borderStyle.none, ""); style.borderRadius 8
                            style.fontWeight 700; style.fontSize 14; style.cursor.pointer
                        ]
                        prop.text (if busy then "Signing in…" else "Sign in")
                    ]
                ]
            ]
        ]
    ]
