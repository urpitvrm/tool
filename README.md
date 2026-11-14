# Sentinel SOC

React and JavaScript SOC workspace with an Express API, PostgreSQL application state, OpenSearch event analytics, and Wazuh Manager agent access. The application uses real upstream query results; it never fills charts or tables with fabricated production events. If an integration is unavailable, the affected view shows an error or empty state.

## Start locally

Requirements: Node.js 20+, PostgreSQL 14+, and access to any OpenSearch or Wazuh services you want to connect.

1. Copy `.env.example` to `.env`. Set a long random `SECRET_KEY` and PostgreSQL values. Fill the OpenSearch and Wazuh connection settings as available. TLS verification remains enabled by default.
2. Create an empty PostgreSQL database using the configured database/user.
3. In one terminal run `cd backend`, `npm install`, `npm run dev`.
4. In another run `cd frontend`, `npm install`, `npm run dev`.
5. Configure SMTP (`SMTP_*` in `.env`). Sign-in requires an emailed verification code; for local work you can use a mail catcher such as Mailpit.
6. Create the first Super Administrator: `cd backend && npm run admin -- create-super-admin --username admin --email you@example.com --name "Your Name"`. Alternatively set `AUTH_SETUP_TOKEN` and use `/setup` in the browser.
7. Open `http://localhost:5173`, sign in with your username or email and password, then enter the code sent to your email.

Authentication, sessions, RBAC and the full auth API are documented in [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).

The browser uses `/api/v1` by default. Vite proxies `/api` to `http://localhost:8000` during local development. The OpenAPI route index is available at `http://localhost:8000/api/v1/openapi.json`; detailed setup notes and supported behavior are in this README.

The backend source is organized by responsibility: root `app.js` configures Express and registers routes, root `server.js` initializes the database and starts the API, `src/config/` contains application and database configuration, and `src/routes/`, `src/controllers/`, `src/services/`, and `src/models/` separate HTTP routes, request handling, business logic, and database queries. Authentication lives in `src/middlewares/`, request schemas in `src/validators/`, shared constants in `src/constants/`, and helpers in `src/utils/`.

## Docker Compose

Copy `.env.example` to `.env`, replace secrets, and configure external OpenSearch and Wazuh endpoints. Compose deploys the web app, API, and PostgreSQL; it does not create duplicate OpenSearch or Wazuh services.

```bash
docker compose build
docker compose up -d
docker compose logs -f
docker compose down
```

PostgreSQL data is retained in the `postgres-data` volume. The frontend Nginx server proxies `/api/` to the API container. For internet-facing use, terminate TLS at a trusted reverse proxy and set an appropriate CORS origin. Never commit `.env`.

## Configuration

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | HS256 signing key and OTP HMAC key; required in production (at least 32 characters) |
| `APP_NAME`, `SUPPORT_CONTACT` | Branding and support contact shown in emails (support contact can be overridden in Application Settings as `auth.support_contact`) |
| `AUTH_SETUP_TOKEN` | One-time token that enables browser setup of the first Super Administrator; unset it afterwards |
| `AUTH_ACCESS_TOKEN_MINUTES`, `AUTH_SESSION_HOURS`, `AUTH_REMEMBER_DAYS` | Access token lifetime (15), session lifetime (12 h), "keep me signed in" lifetime (30 days) |
| `AUTH_OTP_MINUTES`, `AUTH_OTP_MAX_ATTEMPTS`, `AUTH_OTP_RESEND_SECONDS`, `AUTH_OTP_MAX_PER_15_MIN` | Code validity (5), attempts per code (5), resend cooldown (60 s), codes per account per 15 minutes (5) |
| `AUTH_MAX_FAILED_LOGINS`, `AUTH_LOCK_MINUTES` | Lockout threshold (5) and duration (15 min) |
| `AUTH_INVITATION_HOURS`, `AUTH_INVITE_REQUIRES_APPROVAL` | Invitation link lifetime (72 h); require administrator approval after acceptance (false) |
| `AUTH_PASSWORD_HISTORY`, `AUTH_REVOKE_SESSIONS_ON_PASSWORD_CHANGE` | Passwords that cannot be reused (5); sign out other sessions on password change (true) |
| `AUTH_NOTIFY_EVERY_LOGIN`, `AUTH_LOGIN_HISTORY_DAYS` | Email on every sign-in, not only unrecognized ones (false); login history retention (365) |
| `AUTH_COOKIE_SECURE` | Mark cookies `Secure` (defaults to true when `APP_ENV=production`; requires HTTPS) |
| `AUTH_LOGIN_OTP_ENABLED` | `false` skips the sign-in code, for local development without SMTP only |
| `SUPABASE_URL` | Optional Supabase PostgreSQL connection URI; takes precedence over `DATABASE_URL` and uses verified TLS |
| `DATABASE_URL` | Optional PostgreSQL connection string; otherwise `POSTGRESQL_*` variables are used |
| `POSTGRESQL_HOST`, `POSTGRESQL_PORT`, `POSTGRESQL_DB`, `POSTGRESQL_USER`, `POSTGRESQL_PASSWORD` | PostgreSQL connection |
| `OPENSEARCH` | JSON array of one or more OpenSearch node URLs (comma-separated values also accepted) |
| `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` | OpenSearch basic authentication |
| `OPENSEARCH_VERIFY_CERTS` | TLS peer verification; defaults to enabled |
| `OPENSEARCH_REQUEST_TIMEOUT_MS` | OpenSearch request timeout in milliseconds; defaults to 25000 |
| `OPENSEARCH_EVENTS_INDEX` | Event index or pattern; defaults to `wazuh-alerts-*` |
| `MANAGER`, `MANAGER_USERNAME`, `MANAGER_PASSWORD` | Wazuh Manager API connection |
| `WAZUH_REQUEST_TIMEOUT_MS` | Wazuh authentication and API request timeout in milliseconds; defaults to 30000 |
| `WAZUH_VERIFY_TLS` | Wazuh TLS peer verification; defaults to enabled. Set to `false` for a self-signed certificate in local development, or set `WAZUH_CA_FILE` to a trusted CA file. |
| `WAZUH_CA_FILE` | Path to the CA certificate used to verify the Wazuh API certificate |
| `CORS_ORIGINS` | Comma-separated browser origins |
| `TRUST_PROXY` | Set to `1` behind a reverse proxy so rate limits use the client IP (Compose sets this) |
| `OPENSEARCH_ARCHIVES_INDEX` | Optional raw-event index (e.g. `wazuh-archives-*`); enables `source=archives` on `/events` |
| `PUBLIC_BASE_URL` | Browser-facing URL of the app; used to build signed report download links in emails |
| `REPORT_STORAGE_DIR` | Persistent directory for generated report files (default `backend/storage/reports`; the `/app/storage/reports` volume in Docker) |
| `REPORT_MAX_ROWS`, `REPORT_PDF_MAX_ROWS` | Detail-row caps for Excel/CSV (10,000) and PDF (1,000) output |
| `REPORT_RETENTION_DAYS` | Report files older than this are deleted hourly and marked `expired` (default 90) |
| `REPORT_LINK_TTL_HOURS` | Lifetime of emailed download links (default 72) |
| `REPORT_EMAIL_MAX_ATTACHMENT_MB` | Larger reports are emailed as a secure link instead of an attachment (default 10) |
| `REPORT_EMAIL_ALLOWED_DOMAINS` | Optional comma-separated allowlist of recipient domains for all report emails |
| `REPORT_RATE_LIMIT_PER_MINUTE`, `SCHEDULE_RATE_LIMIT_PER_MINUTE` | Per-client limits for report generation/run-now/retry (10) and schedule changes (30) |
| `SCHEDULER_ENABLED` | `false` disables the report scheduler on this instance (default enabled) |
| `SCHEDULER_POLL_INTERVAL_MS`, `SCHEDULER_MAX_ATTEMPTS`, `SCHEDULER_STALE_JOB_MINUTES` | Poll interval (30 s), attempts per execution (3), and when a job held by a crashed worker is reclaimed (30 min) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_VERIFY_TLS` | Nodemailer SMTP settings for scheduled report delivery, kept server-side only |

Use `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` for OpenSearch credentials. Avoid generic `USERNAME` and `PASSWORD` names, which can collide with operating-system environment variables.

For Supabase, use the **PostgreSQL connection string** from the project's Database settings, not only the HTTPS project/API URL. Keep that URI only in the server `.env`; the browser never receives it. The backend enforces TLS certificate verification for `SUPABASE_URL` connections.

## API routes implemented

All routes are under `/api/v1`.

- `GET /health`; authentication under `/auth/*` and user administration under `/users/*` (see [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md))
- `GET /dashboard`, `GET /events` (server-side paging/search), `/agents`, `/agent-groups`
- `/indices`, `/indices/:name/mappings`, `/cluster/health`
- `GET /dashboard` accepts `minutes`, `hours`, or `from`/`to` (ISO-8601) plus the alert filters below, and returns severity bands, timeline, top agents/rules/IPs, rule-group trends and recent alerts in one OpenSearch request
- `GET /events` and `GET /events/export` filters: `from`/`to`/`minutes`/`hours`, `q`, `severity` (critical,high,medium,low), `agent`, `rule_id`, `srcip`, `dstip` (comma-separated, `*` wildcards allowed), `source` (`alerts` or `archives`), `sort`, `order`
- `GET /agents` (`search`, `status`, `group`, `platform`, `sort`, `order`, `exclude_manager`), `GET /agents/summary`, `GET /agents/:id`
- `/custom-dashboards` (list/create) and `/custom-dashboards/:id` (get/update/delete) with widget lists
- `GET /reports/catalog`, `POST /reports/generate`, `/report-history` (paged, with `q`, `report_type`, `status`, `format`, `user_id`), `/report-history/:id`, `/report-history/:id/download`, `DELETE /report-history/:id`, `GET /reports/download/:token` (signed email link)
- `/report-templates` (CRUD)
- `/report-schedules` (CRUD), `/report-schedules/:id/pause|resume|run`, `/report-schedules/:id/executions`, `POST /report-schedules/executions/:executionId/retry`
- `/incidents` (list/create/update/comments), `/saved-searches`
- `/users`, `/roles`, `/permissions`, `/audit-logs`, `/settings`
- Data-backed module queries: `/vulnerabilities`, `/sca`, `/fim`, `/rootcheck`, `/malware`, `/mitre`, `/compliance`, `/assets`, `/rules`, `/decoders`, `/threatIntelligence`

The module query endpoints use configurable/default Wazuh index patterns and return matching source documents only. Exact field mappings and supported Wazuh operations vary by installation. Destructive index/agent actions and provider-specific notification delivery have not been enabled.

## Module workspaces (Dashboard and Search tabs)

Security Events, Alerts, Agents, Vulnerability Detection, Compliance Overview, Security Configuration Assessment, File Integrity Monitoring, Authentication Monitoring, MITRE ATT&CK, Rootcheck, Malware Detection, and the PCI DSS, NIST 800-53, GDPR, HIPAA, CIS Controls and ISO 27001 pages each have two tabs:

- **Dashboard:** KPI cards, a grid of module-specific charts (area, line, stacked bar, bar, horizontal bar, donut, pie), then a detailed table with column selection, sorting, paging, CSV/Excel export and record details. Clicking a chart element opens the matching records in Search.
- **Search:** search bar (simple, or Advanced: Lucene syntax for OpenSearch modules, Wazuh query language for agents) with date range → common filters → Apply / Clear all / Save search / Export CSV → match count and the primary bar graph (Security Events: events by rule level; Alerts: severity; Agents: status; Vulnerabilities: severity; Compliance/SCA: control status; frameworks: control) → matching records table.

Modules are declared in `backend/src/constants/modules.js` (fields, filters, KPIs, charts). Every view of a module is built by `backend/src/services/module.service.js` from one parsed filter set, so the count, charts, table and exports always describe the same records. Aggregations run in OpenSearch or the Wazuh API, never over a page of results in the browser. Agent connection trends come from Wazuh agent lifecycle alerts (rules 501–506), because the Manager API keeps no history.

Sorting is server-side on any keyword, numeric, date, IP or boolean field. Columns can be shown, hidden, reordered, extended with any field in the index mapping, or reset; choices are stored per user, module and table in `user_table_preferences`. Saved searches are stored per module in `saved_searches.module`.

API: `GET /modules`, `/modules/:module`, `/modules/:module/fields`, `/modules/:module/aggregations?scope=dashboard|search`, `/modules/:module/records`, `/modules/:module/values?field=`, `/modules/:module/export?format=csv|xlsx&columns=`, and `GET|PUT|DELETE /modules/:module/preferences/:table`. All accept the same filter parameters: `from`/`to`/`minutes`, `q`, `mode`, and the module's filter keys (for example `level_min`, `level_max`, `rule_id`, `agent_id`, `agent_name`, `srcip`, `dstip`, `event_type`, `protocol`).

## Dashboards, alerts, agents and reporting

- **SOC Dashboard** (`/dashboard`, also `/custom-dashboards`): a customizable widget grid with 15 widgets (severity KPIs, alert trend, severity distribution, top agents/rules/source/destination IPs, recent alerts, agent inventory and connectivity, rule-group trends). Users can keep several dashboards, set a default, add and remove widgets, drag or move them, resize them (1–4 columns), and save the time range and auto-refresh with the layout. Configurations live in PostgreSQL (`saved_dashboards`, `dashboard_widgets`); alert data stays in OpenSearch. Clicking a chart element opens the matching alerts.
- **Alerts, Security Events and Agents** use the module workspaces described above. OpenSearch caps paging at 10,000 hits; exports are not capped for CSV.
- **Reports** (`/reports`): 15 report types (daily/weekly/monthly security, critical, high, security events, agent inventory, agent status, authentication, network, vulnerability, rule distribution, top attacking IPs, executive summary, custom) in PDF, Excel or CSV, with filters, column selection, relative or custom periods, time zone, and saved templates. Every generation is recorded in `report_history`, and files are written to `REPORT_STORAGE_DIR`.
- **Report History** (`/report-history`): search and filter by type, status, format and (with `reports:manage`) user; download or delete.
- **Report Scheduling** (`/report-schedules`): daily, weekly, monthly, or custom cron (requires `reports:manage`, minimum interval 15 minutes) in any IANA time zone, with start/end dates, recipients, optional CC/BCC (`reports:manage`), subject, message, and attachment or secure-link delivery. Shows next/last run, execution and email delivery history, and retry for failed generation or delivery.

Report field mappings follow the Wazuh 4.x alert template (`rule.*`, `agent.*`, `data.srcip`, `data.dstip`, `data.vulnerability.*`). These are plain `keyword` fields without `.keyword` sub-fields. Vulnerability reports read Vulnerability Detector alerts from the alerts index.

### Scheduler design

The scheduler is database-backed rather than an in-memory cron:

1. Each schedule stores its `next_run_at`, computed in the schedule's time zone (DST-aware).
2. On every poll, an instance locks due schedules with `FOR UPDATE SKIP LOCKED`, inserts one `report_execution_history` row per occurrence (`UNIQUE (schedule_id, scheduled_for)` prevents duplicates), and advances `next_run_at`. Occurrences missed during downtime collapse into a single catch-up run.
3. Workers claim queued executions atomically. Generation and email are separate stages, so a failed email is retried without regenerating the report. Transient failures retry with exponential backoff up to `SCHEDULER_MAX_ATTEMPTS`. Jobs held by a crashed worker are reclaimed after `SCHEDULER_STALE_JOB_MINUTES`.
4. The schedule owner's account and `reports:schedule` permission are re-checked at run time, so disabling a user stops their deliveries.

Running several backend instances is safe. Set `SCHEDULER_ENABLED=false` on instances that should only serve the API.

### Permissions

`reports:read` (view the catalog and history, download own reports), `reports:generate` (generate, templates, delete own reports), `reports:schedule` (manage own schedules), `reports:manage` (see and manage every user's reports and schedules, custom cron, CC/BCC). Default roles: Super Administrator, Security Administrator and SOC Manager have all four; Security Analyst and Compliance Analyst have read, generate and schedule; Read Only Analyst has `reports:read`.

### Database migrations

`migrate()` in `src/config/db.js` creates the baseline schema and seeds roles. Versioned migrations in `src/migrations/` (tracked in `schema_migrations`, serialized with an advisory lock) run next on every start. Existing tables are extended rather than duplicated: `saved_dashboards` (dashboards), `report_configurations` (report templates), `report_history`, and `incidents`/`incident_comments` (investigations and notes). New tables: `dashboard_widgets`, `report_schedules`, `report_execution_history`, `email_delivery_history`. Add schema changes as a new numbered migration file; never edit one that has shipped.

## Data and access security

- Argon2id passwords with a strength policy and reuse prevention, mandatory email one-time codes, HttpOnly `SameSite=Strict` cookie sessions with rotating refresh tokens and immediate revocation, double-submit CSRF protection, account lockout, rate limits per IP and per account, multi-role RBAC enforced on every route, login history, and security notification emails. See [docs/AUTHENTICATION.md](docs/AUTHENTICATION.md).
- SQL parameters are bound; API inputs use Zod validation; request bodies are size limited.
- Credentials remain in the API process. OpenSearch TLS verification is enabled by default; provide trusted CA certificates through the Node trust store when needed.
- Audit records capture authentication, incident, account, and settings changes. Never forward raw upstream errors or credentials to logs.
- OpenSearch event documents remain in OpenSearch. PostgreSQL stores app users, roles/permissions, sessions, incidents, searches, asset metadata, settings, dashboards, report metadata, schedules, execution and delivery history, and audit records.
- Report downloads require authentication and ownership (or `reports:manage`). Emailed links are signed, expiring tokens scoped to one report and cannot be used as session tokens. Report generation, downloads, deletions and every schedule change are audit-logged.
- Schedule subjects reject line breaks (header injection), recipients are validated, and recipient domains can be restricted with `REPORT_EMAIL_ALLOWED_DOMAINS`. CSV output neutralizes spreadsheet formula prefixes.
- In production, serve the stack over HTTPS (terminate TLS at a reverse proxy), set `PUBLIC_BASE_URL` to the HTTPS URL, and give the backend a read-only OpenSearch role (dashboards and reports only search).

## Development checks

```bash
cd backend
npm test
```

Backend tests cover schedule time calculations (time zones, DST, month ends, end dates, cron limits), report periods, OpenSearch query building, validators, email retry classification, and the PDF/XLSX/CSV renderers.

```bash
cd frontend
npm run build
```

Integration-dependent pages require reachable services and suitable service-account permissions. The provided `.env` contains placeholder endpoints and credentials, so live cluster discovery cannot succeed until it is configured with reachable services.
