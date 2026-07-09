module Astra.Client.Main

open Browser.Dom
open Fable.Core.JsInterop
open Feliz

importSideEffects "./styles.css"

let root = ReactDOM.createRoot (document.getElementById "root")
root.render (App.App ())
