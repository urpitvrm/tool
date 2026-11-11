# Sentinel SOC

React and JavaScript SOC workspace with an Express API, PostgreSQL application state, OpenSearch event analytics, and Wazuh Manager agent access. The application uses real upstream query results; it never fills charts or tables with fabricated production events. If an integration is unavailable, the affected view shows an error or empty state.

## Start locally

Requirements: Node.js 20+, PostgreSQL 14+, and access to any OpenSearch or Wazuh services you want to connect.

1. Copy `.env.example` to `.env`. Set a long random `SECRET_KEY` and PostgreSQL values. Fill the OpenSearch and Wazuh connection settings as available. TLS verification remains enabled by default.
2. Create an empty PostgreSQL database using the configured database/user.
3. In one terminal run `cd backend`, `npm install`, `npm run dev`.
4. In another run `cd frontend`, `npm install`, `npm run dev`.
5. Open `http://localhost:5173`. On first use, choose **First run? Create the initial admin**. The API permits bootstrap only while the users table is empty.

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
| `SECRET_KEY` | HS256 signing key; required for production |
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

Use `OPENSEARCH_USERNAME` and `OPENSEARCH_PASSWORD` for OpenSearch credentials. Avoid generic `USERNAME` and `PASSWORD` names, which can collide with operating-system environment variables.

For Supabase, use the **PostgreSQL connection string** from the project's Database settings, not only the HTTPS project/API URL. Keep that URI only in the server `.env`; the browser never receives it. The backend enforces TLS certificate verification for `SUPABASE_URL` connections.

## API routes implemented

All routes are under `/api/v1`.

- `GET /health`, `POST /auth/register`, `POST /auth/login`, `GET /auth/me`
- `GET /dashboard`, `GET /events` (server-side paging/search), `/agents`, `/agent-groups`
- `/indices`, `/indices/:name/mappings`, `/cluster/health`
- `/incidents` (list/create/update/comments), `/saved-searches`
- `/users`, `/roles`, `/permissions`, `/audit-logs`, `/settings`
- Data-backed module queries: `/vulnerabilities`, `/sca`, `/fim`, `/rootcheck`, `/malware`, `/mitre`, `/compliance`, `/assets`, `/rules`, `/decoders`, `/threatIntelligence`

The module query endpoints use configurable/default Wazuh index patterns and return matching source documents only. Exact field mappings and supported Wazuh operations vary by installation. Destructive index/agent actions and provider-specific notification delivery have not been enabled.

## Data and access security

- Argon2id password hashing, short-lived signed JWTs, rate-limited login, server-side permission checks, and a bootstrap-only initial admin flow.
- SQL parameters are bound; API inputs use Zod validation; request bodies are size limited.
- Credentials remain in the API process. OpenSearch TLS verification is enabled by default; provide trusted CA certificates through the Node trust store when needed.
- Audit records capture authentication, incident, account, and settings changes. Never forward raw upstream errors or credentials to logs.
- OpenSearch event documents remain in OpenSearch. PostgreSQL stores app users, roles/permissions, sessions, incidents, searches, asset metadata, settings, and audit records.

## Development checks

```bash
cd backend
npm test
```

```bash
cd frontend
npm run build
```

Integration-dependent pages require reachable services and suitable service-account permissions. The provided `.env` contains placeholder endpoints and credentials, so live cluster discovery cannot succeed until it is configured with reachable services.
