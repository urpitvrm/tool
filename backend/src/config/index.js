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
  // Optional index for raw (non-alert) events; Wazuh only writes it when archives are enabled.
  archivesIndex: process.env.OPENSEARCH_ARCHIVES_INDEX || '',
  vulnerabilitiesIndex: process.env.OPENSEARCH_VULNERABILITIES_INDEX || 'wazuh-states-vulnerabilities-*',
  // Public URL of the web app/API, used to build secure report download links in emails.
  publicBaseUrl: (process.env.PUBLIC_BASE_URL || 'http://localhost:5173').replace(/\/+$/, ''),
  reports: {
    storageDir: path.resolve(process.env.REPORT_STORAGE_DIR || fileURLToPath(new URL('../../storage/reports', import.meta.url))),
    maxRows: positiveInteger(process.env.REPORT_MAX_ROWS, 10000),
    pdfMaxRows: positiveInteger(process.env.REPORT_PDF_MAX_ROWS, 1000),
    retentionDays: positiveInteger(process.env.REPORT_RETENTION_DAYS, 90),
    linkTtlHours: positiveInteger(process.env.REPORT_LINK_TTL_HOURS, 72),
    maxAttachmentBytes: positiveInteger(process.env.REPORT_EMAIL_MAX_ATTACHMENT_MB, 10) * 1024 * 1024,
    generateRateLimit: positiveInteger(process.env.REPORT_RATE_LIMIT_PER_MINUTE, 10),
    scheduleRateLimit: positiveInteger(process.env.SCHEDULE_RATE_LIMIT_PER_MINUTE, 30),
    allowedEmailDomains: (process.env.REPORT_EMAIL_ALLOWED_DOMAINS || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean),
  },
  scheduler: {
    enabled: process.env.SCHEDULER_ENABLED !== 'false',
    pollIntervalMs: positiveInteger(process.env.SCHEDULER_POLL_INTERVAL_MS, 30000),
    maxAttempts: positiveInteger(process.env.SCHEDULER_MAX_ATTEMPTS, 3),
    staleJobMinutes: positiveInteger(process.env.SCHEDULER_STALE_JOB_MINUTES, 30),
  },
  auth: {
    appName: process.env.APP_NAME || 'Sentinel SOC',
    supportContact: process.env.SUPPORT_CONTACT || '',
    accessTokenMinutes: positiveInteger(process.env.AUTH_ACCESS_TOKEN_MINUTES, 15),
    sessionHours: positiveInteger(process.env.AUTH_SESSION_HOURS, 12),
    rememberDays: positiveInteger(process.env.AUTH_REMEMBER_DAYS, 30),
    otpMinutes: positiveInteger(process.env.AUTH_OTP_MINUTES, 5),
    otpMaxAttempts: positiveInteger(process.env.AUTH_OTP_MAX_ATTEMPTS, 5),
    otpResendSeconds: positiveInteger(process.env.AUTH_OTP_RESEND_SECONDS, 60),
    otpMaxPerWindow: positiveInteger(process.env.AUTH_OTP_MAX_PER_15_MIN, 5),
    // Login OTP is required. `false` is for local development without SMTP only.
    loginOtpEnabled: process.env.AUTH_LOGIN_OTP_ENABLED !== 'false',
    maxFailedLogins: positiveInteger(process.env.AUTH_MAX_FAILED_LOGINS, 5),
    lockMinutes: positiveInteger(process.env.AUTH_LOCK_MINUTES, 15),
    invitationHours: positiveInteger(process.env.AUTH_INVITATION_HOURS, 72),
    inviteRequiresApproval: process.env.AUTH_INVITE_REQUIRES_APPROVAL === 'true',
    resetGrantMinutes: positiveInteger(process.env.AUTH_RESET_GRANT_MINUTES, 10),
    passwordHistory: positiveInteger(process.env.AUTH_PASSWORD_HISTORY, 5),
    revokeOtherSessionsOnPasswordChange: process.env.AUTH_REVOKE_SESSIONS_ON_PASSWORD_CHANGE !== 'false',
    notifyEveryLogin: process.env.AUTH_NOTIFY_EVERY_LOGIN === 'true',
    loginHistoryDays: positiveInteger(process.env.AUTH_LOGIN_HISTORY_DAYS, 365),
    // One-time token that enables browser-based first Super Admin setup (otherwise use the CLI).
    setupToken: process.env.AUTH_SETUP_TOKEN || '',
    cookieSecure: process.env.AUTH_COOKIE_SECURE ? process.env.AUTH_COOKIE_SECURE === 'true' : process.env.APP_ENV === 'production',
  },
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: positiveInteger(process.env.SMTP_PORT, 587),
    secure: process.env.SMTP_SECURE === 'true',
    user: process.env.SMTP_USER || '',
    password: process.env.SMTP_PASSWORD || '',
    from: process.env.SMTP_FROM || '',
    verifyTls: process.env.SMTP_VERIFY_TLS !== 'false',
  },
};
if (!config.secret && config.environment === 'production') throw new Error('SECRET_KEY must be set in production');
if (!config.secret) config.secret = 'local-development-only-change-this-secret';
if (config.environment === 'production' && config.secret.length < 32) throw new Error('SECRET_KEY must be at least 32 characters in production');
if (config.environment === 'production' && !config.auth.loginOtpEnabled) console.warn('WARNING: AUTH_LOGIN_OTP_ENABLED=false disables login OTP in production.');
