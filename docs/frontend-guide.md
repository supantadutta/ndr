# Astra NDR — Frontend Guide

The analyst console is a **Fable 5 + Feliz** single-page app compiled from F# to
JavaScript and bundled by **Vite**. Source: [`src/Astra.Client`](../src/Astra.Client).

## Stack

- **Fable 5.6** — F# → JS compiler (local tool, `.config/dotnet-tools.json`).
- **Feliz 3** — React-style DSL; components via `[<ReactComponent>]`.
- **Thoth.Json** — typed decoders mirroring the server DTOs.
- **Vite 5** — dev server (proxies `/api`) and production bundler.
- Inline **SVG charts** — no external chart library, so nothing violates a strict CSP.

## Build & run

```bash
cd src/Astra.Client
dotnet tool restore
npm install
dotnet fable watch --run vite     # dev: watch-compile + hot serve on :5173
dotnet fable --run vite build     # production bundle → dist/
```

Fable emits `*.fs.js` next to each `*.fs` (gitignored); `Main.fs.js` is the entry
loaded by `index.html`.

## Structure

- **`Types.fs`** — client records mirroring the API DTOs, plus the `Route` DU and its
  hash parser/printer.
- **`Api.fs`** — `fetch`-based client returning `Result<'T,string>`; one Thoth decoder
  per DTO. Base URL comes from `VITE_API_BASE` (default same-origin).
- **`Theme.fs`** — palette and severity/status/score color helpers.
- **`Charts.fs`** — `horizontalBars` (tactic distribution) and `trendLine` (detection
  trend) as inline SVG.
- **`Components.fs`** — `panel`, `statTile`, `badge`, `scoreChip`, `table`, and the
  `remote` helper that renders loading / error / success for a `Result option`.
- **`Pages/`** — one module per page.
- **`App.fs`** — the shell: grouped sidebar navigation + a hash router
  (`hashchange` listener) selecting the page component.

## Pages

| Route | Page | State |
|-------|------|-------|
| `#/dashboard` | Executive dashboard | ✅ live |
| `#/entities` | Prioritized entity queue | ✅ live |
| `#/entities/{id}` | Entity detail + "why this score" | ✅ live |
| `#/detections` | Detection center (list + evidence detail) | ✅ live |
| `#/incidents` | Incident workbench (list) | ✅ live |
| `#/sensors` | Sensor health | ✅ live |
| `#/attack-graph`, `#/hunting`, `#/detection-engineering`, `#/threat-intel`, `#/response`, `#/admin` | roadmap pages | placeholders naming their delivery phase |

## Data loading pattern

Each page holds `Result<'T,string> option` state, fetches in `useEffectOnce` (or keyed
`useEffect`), and renders via `Components.remote`, which shows a loading state, an error
box, or the success view — consistently across every page.

## Adding a page

1. Add a case to `Route` in `Types.fs` and its hash mapping.
2. Add the API call + decoder in `Api.fs` (if new data).
3. Create `Pages/YourPage.fs` and register it in `App.fs`'s `content` + `navItems`.
