# Astra NDR — Docker Compose

The [`docker-compose.yml`](../docker-compose.yml) stack is the "first runnable" and
demo deployment. Kubernetes manifests come later (Phase 2+).

## Services

| Service | Image | Ports | Role |
|---------|-------|-------|------|
| `postgres` | postgres:16-alpine | 5432 | relational state |
| `redis` | redis:7-alpine | 6379 | cache / queues (Phase 2+) |
| `clickhouse` | clickhouse-server:24-alpine | 8123, 9000 | telemetry tier (Phase 2+) |
| `server` | built from `deploy/server.Dockerfile` | 5170 | central brain |
| `client` | built from `deploy/client.Dockerfile` | 8080→80 | analyst console (nginx) |

## Run

```bash
cp .env.example .env
docker compose up --build
```

- Console: <http://localhost:8080>
- API: <http://localhost:5170>
- The `client` nginx reverse-proxies `/api` → `server:5170`, so the browser talks to a
  single origin.

## What happens on startup

1. `postgres` becomes healthy (healthcheck), then `server` starts.
2. `server` runs `db/migrations/*.sql` (copied into the image at `/app/migrations`).
3. With `ASTRA_SEED_DEMO=true`, the brain seeds synthetic sensors + telemetry and runs
   one analysis pass, so the dashboard is populated immediately.

## Secrets

`.env` supplies `POSTGRES_PASSWORD`, `CLICKHOUSE_PASSWORD`, `ASTRA_SENSOR_TOKEN`. Never
commit a real `.env`. Generate a strong sensor token: `openssl rand -hex 32`.

## Drive the lab sensor against the stack

```bash
python3 lab/demo_sensor.py --api http://localhost:5170 --token "$ASTRA_SENSOR_TOKEN"
```
