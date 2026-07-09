# Astra NDR — Installation

## Prerequisites

| Tool | Version | Why |
|------|---------|-----|
| .NET SDK | **10.x** | Fable 5 tooling targets net10; also builds the net8 server/shared |
| Node.js | 18+ | Vite bundler for the console |
| Docker + Compose | recent | full-stack option |
| Python | 3.8+ | lab sensor simulator (optional) |

> The server and shared projects target **net8.0** and build/run on the .NET 10 SDK
> too. The Fable **tool** requires the .NET 10 SDK to install and run.

## Local development

```bash
# clone, then:

# --- backend ---
dotnet build AstraNdr.sln
dotnet run --project src/Astra.Server
#   → http://localhost:5170 (seeds a demo environment on first run)

# --- frontend ---
cd src/Astra.Client
dotnet tool restore        # installs Fable 5 from .config/dotnet-tools.json
npm install
dotnet fable watch --run vite
#   → http://localhost:5173 (proxies /api to :5170)
```

## Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `ASTRA_POSTGRES` | *(empty)* | Postgres connection string; empty → in-memory only |
| `ASTRA_MIGRATIONS_PATH` | `<bin>/migrations` | location of `*.sql` migrations |
| `ASTRA_SENSOR_TOKEN` | `dev-sensor-token-change-me` | sensor ingestion token |
| `ASTRA_SEED_DEMO` | `true` | seed synthetic demo data when store is empty |
| `ASTRA_CORS_ORIGINS` | `http://localhost:5173` | comma-separated allowed origins |
| `ASTRA_DETECTION_WINDOW_MIN` | `30` | detection sliding-window minutes |
| `ASTRA_DETECTION_INTERVAL_SEC` | `15` | analysis-cycle interval |
| `ASPNETCORE_URLS` | `http://localhost:5170` | server bind address |

## Production build

```bash
dotnet publish src/Astra.Server -c Release -o out/server
cd src/Astra.Client && dotnet fable --run vite build   # → dist/
```

Or use Docker — see [`docker-compose.md`](docker-compose.md).

## Troubleshooting

- **`DotnetToolSettings.xml not found` installing Fable** — you're on an older SDK. Fable
  5 needs the .NET 10 SDK.
- **Console shows "Failed to load"** — the backend isn't running or CORS/proxy is
  misconfigured. In dev, Vite proxies `/api`; check `vite.config.js`.
- **No detections after ingest** — detections run on the analysis interval; wait one
  cycle (default 15 s) or lower `ASTRA_DETECTION_INTERVAL_SEC`.
