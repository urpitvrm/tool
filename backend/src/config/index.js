import dotenv from 'dotenv';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const backendEnvPath = fileURLToPath(new URL('../../.env', import.meta.url));
const workspaceEnvPath = fileURLToPath(new URL('../../../.env', import.meta.url));
const defaultEnvPath = existsSync(backendEnvPath) ? backendEnvPath : workspaceEnvPath;
dotenv.config({ path: path.resolve(process.env.ENV_FILE || defaultEnvPath) });

function list(value = '[]') {
  try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed : [parsed]; }
  catch { return value.split(',').map((x) => x.trim()).filter(Boolean); }
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export const config = {
  port: Number(process.env.PORT || 8000),
  environment: process.env.APP_ENV || 'development',
  secret: process.env.SECRET_KEY || '',
  databaseUrl: process.env.SUPABASE_URL || process.env.DATABASE_URL || '',
  usingSupabase: Boolean(process.env.SUPABASE_URL),
  databaseTls: Boolean(process.env.SUPABASE_URL) || process.env.PGSSL === 'true',
  pg: { host: process.env.POSTGRESQL_HOST || 'localhost', port: Number(process.env.POSTGRESQL_PORT || 5432), database: process.env.POSTGRESQL_DB || 'siem', user: process.env.POSTGRESQL_USER || 'siem', password: process.env.POSTGRESQL_PASSWORD || '' },
  searchNodes: list(process.env.OPENSEARCH || '[]'),
  searchUsername: process.env.OPENSEARCH_USERNAME || '',
  searchPassword: process.env.OPENSEARCH_PASSWORD || '',
  opensearchRequestTimeoutMs: positiveInteger(process.env.OPENSEARCH_REQUEST_TIMEOUT_MS, 25000),
  verifyTls: process.env.OPENSEARCH_VERIFY_CERTS !== 'false',
  wazuhRequestTimeoutMs: positiveInteger(process.env.WAZUH_REQUEST_TIMEOUT_MS, 30000),
  wazuhVerifyTls: process.env.WAZUH_VERIFY_TLS !== 'false',
  wazuhCaFile: process.env.WAZUH_CA_FILE || '',
  eventsIndex: process.env.OPENSEARCH_EVENTS_INDEX || 'wazuh-alerts-*',
  manager: process.env.MANAGER || '', managerUser: process.env.MANAGER_USERNAME || '', managerPassword: process.env.MANAGER_PASSWORD || '',
  corsOrigins: (process.env.CORS_ORIGINS || 'http://localhost:5173').split(',').map((x) => x.trim()),
};
if (!config.secret && config.environment === 'production') throw new Error('SECRET_KEY must be set in production');
if (!config.secret) config.secret = 'local-development-only-change-this-secret';
