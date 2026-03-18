# PocketSOC

PocketSOC delivers a fast, mobile-friendly way to access Rapid7 InsightIDR, helping SOC analysts triage alerts and investigate incidents from anywhere.

> Disclaimer: PocketSOC is a community project and is not officially supported, endorsed, or maintained by Rapid7.

## Architecture

- `backend/` is an Express proxy and normalization layer for Rapid7 InsightIDR APIs.
- `frontend/` is a framework-free Vite app tuned for phone-sized alert review and case response.
- The production container serves both layers from the same origin on port `3000`.

## Highlights

- Per-browser remembered sessions with encrypted stored config.
- Alert queue, investigation queue, and health overview in one UI.
- Alert detail enrichment for evidences, actors, process trees, rule summaries, MITRE, logsets, and event sources.
- Investigation detail workflows for status/priority/disposition changes, reassignment, comments, and attachments.
- Docker image and GitHub Actions workflow for CI plus optional Docker Hub publishing.

## Screenshots

### Alerts Desktop

![PocketSOC alerts desktop view](docs/screenshots/01-PocketSOC-Alerts-Desktop.png)

### Alerts Mobile

![PocketSOC alerts mobile view](docs/screenshots/02-PocketSOC-Alerts-Mobile.png)

### Alert Stacking

![PocketSOC hybrid alert stack view](docs/screenshots/03-PocketSOC-Alerts-Hybrid-Stack.png)

### Alert Details and Triage Pivots

![PocketSOC alert details and triage pivots](docs/screenshots/04-PocketSOC-Alert-Details+Triage-Pivots.png)

### Automatic Base64 Decoding

![PocketSOC base64 alert workflow](docs/screenshots/05-PocketSOC-Alert-Base64.png)

### Investigation Overview

![PocketSOC investigation overview](docs/screenshots/06-PocketSOC-Investigation-Overview.png)

### Investigation Details

![PocketSOC investigation details](docs/screenshots/07-PocketSOC-Investigation-Details.png)

### Health Overview

![PocketSOC health overview](docs/screenshots/08-PocketSOC-Health-Overview.png)

## Quick Start

1. Install dependencies:

```bash
cd backend && npm install
cd ../frontend && npm install
```

2. Run the backend and frontend together from the repo root:

```bash
npm run dev
```

3. Open the frontend at `http://localhost:5173`.

4. In the PocketSOC settings view, enter:

- an Insight Platform API key with access to the InsightIDR APIs
- a supported region: `us`, `eu`, `ca`, or `ap`

The app remembers config per browser for 90 days by storing an encrypted server-side session blob and a secure `HttpOnly` session cookie.

## Configuration

Environment variables:

- `POCKETSOC_CONFIG_FILE`: path to persisted session state, default `backend/local/config.json`
- `POCKETSOC_SESSION_SECRET_FILE`: optional override for the auto-generated secret file when `POCKETSOC_SESSION_SECRET` is not provided. By default, PocketSOC writes `session-secret.hex` next to `POCKETSOC_CONFIG_FILE`
- `POCKETSOC_SESSION_SECRET`: optional stable secret used to encrypt remembered browser configs
- `POCKETSOC_ATTACHMENT_MAX_BYTES`: optional upload cap for proxied attachment uploads, default `26214400` (25 MiB)
- `POCKETSOC_FORCE_SECURE_COOKIE`: optional `true`/`false` override that forces the session cookie to include `Secure`, useful behind TLS-terminating proxies that do not forward HTTPS information cleanly

Recommended local state path:

```bash
cp .env.example .env
```

PocketSOC defaults to `./backend/local/config.json`, which is ignored by both Git and the Docker build context. When `POCKETSOC_SESSION_SECRET` is omitted, PocketSOC auto-creates `session-secret.hex` next to that config file by default.

The listen port is intentionally not exposed in `.env.example`. Docker users change only the host-side published port when needed.

## Docker

Pull the published image from Docker Hub:

```bash
docker pull philippbehmer/rapid7-insightidr-mobile-console:latest
```

Run it with persistent session storage:

```bash
docker volume create pocketsoc-data
docker run --rm -p 3000:3000 \
  -e POCKETSOC_CONFIG_FILE=/app/data/config.json \
  -v pocketsoc-data:/app/data \
  philippbehmer/rapid7-insightidr-mobile-console:latest
```

Or use Compose, which defaults to the same published image and persists both files in the named volume:

```bash
docker compose pull
docker compose up -d
```

Notes:

- If port `3000` is already in use, change only the host-side port:

```bash
docker run --rm -p 3001:3000 \
  -e POCKETSOC_CONFIG_FILE=/app/data/config.json \
  -v pocketsoc-data:/app/data \
  philippbehmer/rapid7-insightidr-mobile-console:latest
```

- Compose supports the same host-port override via `POCKETSOC_HOST_PORT`:

```bash
export POCKETSOC_HOST_PORT=3001
docker compose pull
docker compose up -d
```

- If you prefer to provide the encryption secret yourself instead of letting PocketSOC generate one, set `POCKETSOC_SESSION_SECRET` before `docker run` or `docker compose up`. If you want the generated secret file in a different location, set `POCKETSOC_SESSION_SECRET_FILE` before `docker compose up` or pass it with `-e` to `docker run`.

- `POCKETSOC_FORCE_SECURE_COOKIE=true` is only needed in deployments where HTTPS terminates before the app and the proxy does not forward the original scheme correctly. Normal local Docker use should leave it unset.

- If you want to build and run the image from your checked-out source instead, that remains a separate local workflow:

```bash
docker build -t pocketsoc:local .
docker run --rm -p 3000:3000 \
  -e POCKETSOC_CONFIG_FILE=/app/data/config.json \
  -v pocketsoc-data:/app/data \
  pocketsoc:local
```

- If you do not provide `POCKETSOC_SESSION_SECRET`, keep `POCKETSOC_CONFIG_FILE` and the generated `session-secret.hex` on persistent storage across restarts or stored browser configs will no longer decrypt.
- The runtime container now runs as a non-root user.
- In production, the backend serves the built frontend from `frontend/dist` on the same origin as `/api`.

## Testing

Current automated checks:

```bash
cd backend && npm test
cd frontend && npm test
```

- Backend tests cover session/config behavior, selected route contracts, and attachment streaming paths.
- Frontend `npm test` is currently a production build smoke check, not a browser interaction suite.

## Repository Layout

- `backend/server.js`: backend routes, Rapid7 proxy logic, session/config persistence, response shaping, caches
- `backend/server.test.js`: backend smoke and regression tests
- `frontend/main.js`: app state, fetch orchestration, navigation, overlay logic
- `frontend/components.js`: rendering helpers and the main frontend XSS boundary
- `frontend/style.css`: UI system and layout
- `Dockerfile`: multi-stage production build
- `compose.yaml`: local container runtime example
- `AGENTS.md`: repository-specific working notes for future coding sessions
