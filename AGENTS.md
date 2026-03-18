# Repository Guidelines

## Project Overview
- This repo is a two-part InsightIDR client:
- `backend/` is an Express proxy and normalization layer for Rapid7 InsightIDR APIs.
- `frontend/` is a Vite-built, framework-free mobile-oriented UI branded as PocketSOC.
- The app is designed around alert triage and investigation workflows, not generic CRUD.
- `AGENTS.md` is pushed to GitHub; treat it as public operational documentation and never include real secrets, customer identifiers, internal-only URLs, or environment-specific sensitive values.

## Project Structure & Ownership
- `backend/server.js`: all backend routes, config persistence, Rapid7 proxy logic, response shaping, and small in-memory caches.
- `backend/local/config.json`: default local runtime session store persisted by the backend. It keeps encrypted per-browser config blobs plus session metadata, so treat it as sensitive local state.
- `backend/local/session-secret.hex`: default local encryption secret path generated when `POCKETSOC_SESSION_SECRET` is not set and `POCKETSOC_SESSION_SECRET_FILE` is not overridden. Never commit it.
- `Dockerfile`: multi-stage production image that builds the Vite frontend, installs backend production dependencies, and serves the app from the backend on port `3000`.
- `compose.yaml`: local container runtime example for the published Docker Hub image, with a named volume mounted at `/app/data` for persisted session state; the auto-generated session secret follows that same directory by default.
- `.github/workflows/docker-publish.yml`: CI workflow that runs the backend/frontend checks on pull requests and publishes a multi-arch Docker Hub image on pushes to `main`.
- `.env.example`: local environment template for optional overrides; PocketSOC already defaults persisted session state to `backend/local/`, the auto-generated secret follows that same directory by default, and backend `PORT` remains intentionally omitted because normal user flows should rely on the default internal port.
- `.gitignore` and `.dockerignore`: release hygiene files; keep custom session-state paths and local secrets ignored when examples or persistence paths change.
- `frontend/main.js`: `MainApp` singleton, view templates, event wiring, fetch orchestration, overlay navigation, and client-side state.
- `frontend/components.js`: HTML rendering helpers for lists, detail panels, badges, forms, and empty states.
- `frontend/style.css`: the full visual system for the glass-panel mobile console UI.
- `frontend/index.html`: shell markup and external font imports.
- `frontend/vite.config.js`: serves the UI on port `5173` and proxies `/api` to `http://localhost:3000`.
- `frontend/dist/`: generated build output. Do not hand-edit built assets; rebuild with Vite after source changes.
- `node_modules/` and lockfiles in both apps are generated dependency artifacts, not source.

## Runtime Behavior & Config
- Each browser gets its own remembered session backed by a secure `HttpOnly` cookie and a stored config shaped like `{ apiKey, platformUserApiKey, region }`.
- The settings screen currently exposes only the primary `apiKey` plus `region`; `platformUserApiKey` remains backend-only legacy state until Rapid7 platform-user lookup behavior is clarified.
- In production container runs, the Express backend serves the built frontend from `frontend/dist` on the same origin as `/api` when `NODE_ENV=production`.
- `POCKETSOC_CONFIG_FILE` can override the default `backend/local/config.json` path for isolated local test runs.
- `POCKETSOC_SESSION_SECRET_FILE` can override the generated-secret path explicitly; otherwise the backend writes `session-secret.hex` next to `POCKETSOC_CONFIG_FILE`.
- `POCKETSOC_SESSION_SECRET` can provide the encryption secret for stored session configs; otherwise the backend generates a local secret file at the derived or overridden path.
- `POCKETSOC_ATTACHMENT_MAX_BYTES` can cap proxied attachment uploads; the default is `26214400` (25 MiB).
- `POCKETSOC_FORCE_SECURE_COOKIE=true` forces the session cookie to include `Secure`; this is mainly for TLS-terminating proxy setups where HTTPS is not detected from the request itself.
- `GET /api/config` intentionally returns only booleans plus `region`; it never returns raw keys.
- `POST /api/config` only overwrites fields that are present and non-empty, so blank inputs do not clear saved keys for the current browser session.
- `POST /api/config` trims API-key fields before deciding whether they are usable, so whitespace-only values are treated as unset.
- `POST /api/config` rejects unsupported regions; the current allowlist is `us`, `eu`, `ca`, and `ap`.
- `POST /api/config/clear` clears stored credentials for the current browser session but intentionally preserves `region`.
- Browser sessions are remembered for 90 days and the expiry rolls forward on active use.
- Region drives both the main Insight platform host and the separate log search host.
- The `today` time filter is calculated from UTC midnight in `backend/server.js`, not the browser's local timezone.
- Most outbound Rapid7 requests now use a shared 20-second timeout and surface timeout failures as `504` responses.
- The backend defaults to port `3000`; the frontend dev server defaults to `5173`.

## Backend API Surface
- Config routes:
- `GET /api/config`
- `POST /api/config`
- `POST /api/config/clear`
- Health route:
- `GET /api/health-metrics/overview`
- Supporting lookup routes:
- `GET /api/analysts`: platform user lookup via `/account/api/1/users`; uses `platformUserApiKey` when present and caches results for 5 minutes.
- If Rapid7 continues denying org admin keys for platform-user lookup, remove the `platformUserApiKey` code path entirely instead of re-exposing it in the UI.
- `GET /api/logsets/resolve`: resolves logset IDs against the log search API and caches names for 30 minutes.
- `GET /api/event-sources/resolve`: resolves event source RRNs from health-metrics inventory first, then optionally from log search event-source mappings.
- `GET /api/mitre/resolve`: resolves MITRE tactic and technique codes from a cached ATT&CK catalog downloaded from GitHub.
- Alert routes:
- `GET /api/alerts`: searches alert RRNs by time window, then hydrates full alert records in batches.
- `PATCH /api/alerts/:id`: updates alert `status`, `priority`, `disposition`, `assignee_id`, and `investigation_rrn`.
- `GET /api/alerts/:id/evidences`
- `GET /api/alerts/:id/actors`
- `GET /api/alerts/:id/process-trees`
- `POST /api/alerts/:id/investigate`: creates an investigation from an alert search term.
- `GET /api/rules/:rrn/summary`: pulls detection-rule summary data for selected items.
- Investigation routes:
- `GET /api/investigations`
- `POST /api/investigations`
- `GET /api/investigations/:id`
- `GET /api/investigations/:id/alerts`: merges investigation alert summaries with triage alert details.
- `GET /api/investigations/:id/actors`: prefers direct actor lookup, then falls back to aggregating actors across linked alerts.
- `GET /api/investigations/:id/comments`
- `POST /api/investigations/:id/comments`
- `GET /api/investigations/:id/attachments`
- `PATCH /api/investigations/:id`: uses a v2 PATCH for general fields and assignee changes, then dedicated PUT calls for priority, status, and standalone disposition updates.
- Attachment routes:
- `POST /api/attachments`
- `GET /api/attachments/:rrn/download`
- Rapid7 behavior is split across `/idr/at`, `/idr/v1`, and `/idr/v2`; preserve those endpoint families unless the API docs clearly say otherwise.

## Frontend Architecture & UX Notes
- The frontend is plain ES modules with no framework or state library.
- `MainApp.data` is the main state container for config, alerts, investigations, analysts, logset names, selected detail item, and time-range filters.
- Views are inline template strings in `frontend/main.js`, then injected into `#main-content`.
- The detail experience is an overlay with its own history stack, so related alert/investigation cards can drill in and back out without leaving the list view.
- Primary alert, investigation, and stack cards are keyboard-activatable; preserve their `role`, `tabindex`, and key handling if card markup changes.
- The detail overlay now behaves as a dialog with focus trapping and focus restore on close; keep that behavior intact when editing `frontend/main.js`.
- Alert detail hydration loads evidences, actors, process trees, optional linked investigation data, and rule summaries.
- Investigation detail hydration loads full detail plus related alerts and actors.
- Investigation detail hydration also loads comments and attachments, and the detail view supports comment creation plus file upload.
- Analyst assignment fields use a debounced lookup backed by `/api/analysts`.
- Alert and investigation update forms now submit diff-only payloads instead of re-sending every visible field on every save.
- Log details may start with raw `logset_id` values, then re-render after async name resolution through `/api/logsets/resolve`.
- Event source labels may start as RRNs and then re-render after async resolution through `/api/event-sources/resolve`.
- MITRE tactic and technique labels are resolved lazily from `/api/mitre/resolve` after rule summaries load.
- Current UI time filters expose `today`, `7d`, and `28d`; backend helpers also support `3m` and `6m` if the UI is extended later.
- Most UI rendering still uses `innerHTML` template strings, so `frontend/components.js` is the main XSS boundary.

## Review Notes & Sharp Edges
- Treat every API-derived string as untrusted when editing `frontend/components.js` or `frontend/main.js`. The main list/detail surfaces are now escaped more consistently, but this frontend still relies heavily on `innerHTML`, so new fields need deliberate escaping.
- Avoid reintroducing generic raw-HTML passthroughs in `frontend/components.js`; use narrowly scoped trusted render helpers and validate external URLs before rendering links.
- Alert unassignment is still not supported by the documented alert-triage patch contract, and the frontend now blocks that action explicitly instead of failing silently.
- Investigation assignees can be cleared by sending `assignee: { email: null }` through the v2 patch payload. If you touch that path, preserve the distinction between omitted assignee updates and explicit unassignment.
- Investigation disposition updates are still subtle: the frontend now sends diff-only payloads, and the form includes a `No change` placeholder so blank current dispositions do not silently become `BENIGN`.
- Progressive investigation hydration must not wipe in-progress form edits or comment drafts; preserve the dirty-form guards in `frontend/main.js` if that refresh flow changes.
- Alert and investigation list fetches now surface backend error messages instead of collapsing non-OK responses into empty-state data. If a queue looks empty, check whether the request truly succeeded before debugging filters.
- `GET /api/alerts` now does an upfront API-key guard and preserves upstream status/error bodies, so frontend debugging should use the real response code rather than assuming a generic 500.
- Add obvious AGENTS.md reminders whenever a change affects the repo guidance so future sessions keep the instruction about updating this file.
- The MITRE resolver depends on downloading the ATT&CK catalog from GitHub and caches it in memory for 12 hours, so first-load failures can be network-related rather than Rapid7-related.

## Build, Test, and Development Commands
- Repo root convenience command:
- `npm run dev` starts both `backend/node server.js` and `frontend/npm run dev`; stop both with `Ctrl+C`
- `docker build -t pocketsoc:local .`
- `docker pull philippbehmer/rapid7-insightidr-mobile-console:latest`
- `docker compose pull && docker compose up -d`
- Run commands from the relevant app directory.
- `cd backend && npm install`
- `cd backend && npm run dev`
- `cd backend && node server.js`
- `cd backend && npm test`
- `cd frontend && npm install`
- `cd frontend && npm run dev`
- `cd frontend && npx vite --host 0.0.0.0 --port 5173`
- `cd frontend && npx vite build`
- `cd frontend && npm test` currently runs a Vite production build as a smoke check.
- `cd backend && npm test` runs the backend smoke suite.

## Coding Style & Change Boundaries
- Match existing indentation: backend is mostly 4 spaces, frontend is 2 spaces.
- Use `camelCase` for variables/functions and `UPPER_SNAKE_CASE` for constants.
- Keep backend request shaping and Rapid7-specific normalization in `backend/server.js`.
- Keep rendering helpers in `frontend/components.js` and orchestration/state in `frontend/main.js`.
- Preserve the current visual language in `frontend/style.css`: dark glass panels, orange accent, Rajdhani/Space Grotesk typography.
- Avoid editing `frontend/dist/` directly unless the task is specifically about generated output.

## Testing & Validation
- There is now a small backend smoke suite in `backend/server.test.js`, but coverage is still limited and there is no broader automated frontend or integration suite yet.
- Backend smoke tests now live in `backend/server.test.js`; keep them aligned with route contracts when config, alerts, investigations, or attachment validation behavior changes.
- Backend validation should use `curl` or browser requests against `http://localhost:3000`.
- Frontend validation should cover:
- saving config and reloading connection state
- negative config states such as missing/invalid API keys and empty-list error handling
- loading alerts and investigations for each visible time range
- checking the `today` range near UTC date boundaries if time filtering is changed
- opening alert and investigation detail overlays
- updating alert status, priority, disposition, and assignee
- updating investigation status, priority, disposition, and assignee
- verifying investigation unassignment and confirming alert unassignment still shows the explicit unsupported-action message
- creating an investigation from an alert
- nested detail navigation between related alerts and investigations
- delayed analyst suggestions and delayed logset-name resolution
- delayed event-source-name resolution and delayed MITRE label resolution
- health overview loading, partial-data scenarios, and error rendering
- investigation comments, attachment upload, and attachment download
- If new tests are added, place them near source files with `*.test.js` naming and add runnable scripts in the relevant `package.json`.

## Security & Repo Hygiene
- Never commit real API keys or repeat them in docs, code comments, screenshots, or task notes.
- `backend/local/config.json` and `backend/local/session-secret.hex` are local runtime secrets/state and should use sanitized values before commits or sharing.
- `backend/local/` is the recommended place for alternate local persisted session state; auto-generated secrets will follow that directory by default, so keep it ignored if examples or tooling change.
- The backend tightens local permissions on `backend/local/config.json`, `backend/local/session-secret.hex`, and overridden secret/config paths to owner-only (`0600`) when it reads or writes them.
- Prefer environment-based secrets for shared environments when extending deployment support.
- For container deployments, either provide `POCKETSOC_SESSION_SECRET` outside the image or persist `POCKETSOC_CONFIG_FILE` on a volume so the generated sibling `session-secret.hex` survives restarts as well; override `POCKETSOC_SESSION_SECRET_FILE` only when a separate location is required.
- The production container now runs as an unprivileged `pocketsoc` user; preserve that when editing `Dockerfile` or Compose examples.
- Docker Hub publishing relies on GitHub secrets `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, and the repository variable `DOCKERHUB_REPOSITORY`; treat those as deployment configuration, not source-controlled values.
- The Docker publish workflow now skips registry login/push when those GitHub settings are missing instead of failing the whole push build.
- `.gitignore` and `.dockerignore` should keep `backend/local/`, env files, and other sensitive local artifacts out of source control.

## Public Release Checklist
- The project is currently published without a root `LICENSE` file; keep repo guidance and release notes consistent with that state until the licensing decision changes.
- Keep `README.md`, `.env.example`, `.gitignore`, `.dockerignore`, and `.github/workflows/docker-publish.yml` aligned when changing setup or persistence guidance.
- Re-read `README.md` before release and verify documented commands, environment variables, image names, ports, and persistence guidance still work as written.
- Sanitize screenshots, sample values, local runtime state, and any shared config artifacts before release so no API keys, tenant identifiers, or sensitive investigation data are exposed.
- Confirm `.gitignore` and `.dockerignore` still exclude `backend/local/`, env files, logs, and other sensitive local artifacts after any setup or deployment changes.
- Run `cd backend && npm test` and `cd frontend && npm test` before release.
- Run `docker build -t pocketsoc:local .` and a basic container smoke test for the documented Docker flow before release.
- Confirm GitHub Actions and Docker Hub publishing settings still match the intended public release behavior, including the optional-skip path when registry secrets or variables are unset.
- Verify screenshots, branding, and disclaimer text are still safe for public distribution and do not imply official Rapid7 support beyond the stated community-project disclaimer.

## Commit & Pull Request Guidelines
- Local git history is not available in this workspace, so use this baseline convention:
- Commit format: `type(scope): imperative summary`
- Example: `feat(frontend): add alert status filter`
- Keep commits small and single-purpose.
- PRs should include what changed, why, manual test steps, and screenshots or GIFs for UI updates.
- Link related issue/task IDs and call out config or API contract changes explicitly.

## API References
- Use the Rapid7 InsightIDR API documentation as the primary source of truth for endpoint behavior and payloads:

- `https://docs.rapid7.com/insight/api-overview/`

### Multi Tenant APIs
- `https://docs.rapid7.com/insight/managing-multi-tenant-api-keys/`

### Product APIs
- `https://docs.rapid7.com/insightidr/insightidr-rest-api/`
- `https://help.rapid7.com/insightidr/en-us/api/v1/insightidr-api-v1.json`
- `https://help.rapid7.com/insightidr/en-us/api/v2/insightidr-api-v2.json`
- `https://docs.rapid7.com/_api/insightidr-alert-triage.yaml`
- `https://docs.rapid7.com/_api/insightidr-log-search.yaml`
