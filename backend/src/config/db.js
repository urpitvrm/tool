
import pg from 'pg';
import { config } from './index.js';

const { Pool } = pg;

// Return DATE columns as 'YYYY-MM-DD' strings. The default parser builds a Date at local
// midnight, which shifts calendar dates (e.g. schedule start/end dates) across time zones.
pg.types.setTypeParser(1082, (value) => value);

const DATABASE_URL = config.databaseUrl;

if (!DATABASE_URL) {
  throw new Error('Set SUPABASE_URL or DATABASE_URL in the backend environment.');
}

export const pool = new Pool({
  connectionString: DATABASE_URL,
  max: 15,
  connectionTimeoutMillis: 8000,
  idleTimeoutMillis: 30000,

  // Development workaround only
  ssl: config.databaseTls ? { rejectUnauthorized: false } : undefined,
});

pool.on('error', (error) => {
  console.error('PostgreSQL pool error:', error.message);
});

// Keep your existing migrate() and audit() functions below.

// Database migrations
export async function migrate() {
  console.log('Starting database migrations...');
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS roles (
        id SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        permissions JSONB NOT NULL DEFAULT '[]'
      );

      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role_id INTEGER NOT NULL REFERENCES roles(id),
        disabled BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        detail JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE INDEX IF NOT EXISTS audit_logs_created_idx
      ON audit_logs(created_at DESC);

      CREATE TABLE IF NOT EXISTS incidents (
        id BIGSERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'New',
        severity TEXT NOT NULL DEFAULT 'medium',
        assigned_to TEXT,
        description TEXT NOT NULL DEFAULT '',
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS incident_comments (
        id BIGSERIAL PRIMARY KEY,
        incident_id BIGINT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id),
        body TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS saved_searches (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        query JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE(user_id, name)
      );

      CREATE TABLE IF NOT EXISTS asset_metadata (
        agent_id TEXT PRIMARY KEY,
        owner TEXT,
        classification TEXT,
        importance INTEGER NOT NULL DEFAULT 3,
        metadata JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS application_settings (
        key TEXT PRIMARY KEY,
        value JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS integration_settings (
        provider TEXT PRIMARY KEY,
        enabled BOOLEAN NOT NULL DEFAULT false,
        config JSONB NOT NULL DEFAULT '{}',
        secret_ciphertext TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS notification_channels (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        enabled BOOLEAN NOT NULL DEFAULT false,
        config JSONB NOT NULL DEFAULT '{}',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS notification_rules (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        condition JSONB NOT NULL,
        channel_id BIGINT REFERENCES notification_channels(id) ON DELETE SET NULL,
        enabled BOOLEAN NOT NULL DEFAULT true
      );

      CREATE TABLE IF NOT EXISTS custom_rule_metadata (
        rule_id TEXT PRIMARY KEY,
        metadata JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS report_configurations (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        report_type TEXT NOT NULL,
        schedule TEXT,
        options JSONB NOT NULL DEFAULT '{}',
        enabled BOOLEAN NOT NULL DEFAULT false,
        created_by INTEGER REFERENCES users(id)
      );

      CREATE TABLE IF NOT EXISTS report_history (
        id BIGSERIAL PRIMARY KEY,
        configuration_id BIGINT REFERENCES report_configurations(id) ON DELETE SET NULL,
        status TEXT NOT NULL,
        artifact_path TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );

      CREATE TABLE IF NOT EXISTS saved_dashboards (
        id BIGSERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        layout JSONB NOT NULL DEFAULT '{}'
      );

      CREATE TABLE IF NOT EXISTS dashboard_preferences (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        preferences JSONB NOT NULL DEFAULT '{}'
      );

      CREATE TABLE IF NOT EXISTS permissions (
        id SERIAL PRIMARY KEY,
        key TEXT UNIQUE NOT NULL,
        description TEXT NOT NULL DEFAULT ''
      );

      CREATE TABLE IF NOT EXISTS role_permissions (
        role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
        permission_id INTEGER REFERENCES permissions(id) ON DELETE CASCADE,
        PRIMARY KEY(role_id, permission_id)
      );

      CREATE TABLE IF NOT EXISTS user_roles (
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        role_id INTEGER REFERENCES roles(id) ON DELETE CASCADE,
        PRIMARY KEY(user_id, role_id)
      );
    `);

    // Permissions
    const permissions = [
      'dashboard:read',
      'events:read',
      'hunt:write',
      'incidents:write',
      'agents:read',
      'agents:manage',
      'indices:read',
      'indices:manage',
      'reports:read',
      'reports:generate',
      'reports:schedule',
      'reports:manage',
      'admin:users',
      'admin:settings',
      'audit:read',
      'compliance:read',
      'assets:write',
    ];

    for (const permission of permissions) {
      await client.query(
        `INSERT INTO permissions(key)
         VALUES($1)
         ON CONFLICT(key) DO NOTHING`,
        [permission]
      );
    }

    // Default roles
    const roles = [
      'Super Administrator',
      'Security Administrator',
      'SOC Manager',
      'Security Analyst',
      'Threat Hunter',
      'Compliance Analyst',
      'Read Only Analyst',
      'SOC Analyst',
      'Auditor',
      'Report Viewer',
    ];

    for (const role of roles) {
      let perms;

      if (role === 'Super Administrator') {
        perms = permissions;
      } else if (role === 'Security Administrator') {
        perms = permissions.filter(p => p !== 'admin:users');
      } else if (role === 'Threat Hunter') {
        perms = [
          'dashboard:read',
          'events:read',
          'hunt:write',
          'incidents:write',
          'agents:read',
          'indices:read',
        ];
      } else if (role === 'Compliance Analyst') {
        perms = [
          'dashboard:read',
          'events:read',
          'compliance:read',
          'reports:read',
          'reports:generate',
          'reports:schedule',
        ];
      } else if (role === 'Read Only Analyst') {
        perms = permissions.filter(p => p.endsWith(':read'));
      } else if (role === 'SOC Analyst') {
        perms = ['dashboard:read', 'events:read', 'incidents:write', 'agents:read', 'reports:read'];
      } else if (role === 'Auditor') {
        perms = ['dashboard:read', 'events:read', 'agents:read', 'audit:read', 'compliance:read', 'reports:read'];
      } else if (role === 'Report Viewer') {
        perms = ['dashboard:read', 'reports:read'];
      } else {
        perms = [
          'dashboard:read',
          'events:read',
          'hunt:write',
          'incidents:write',
          'agents:read',
          'reports:read',
          'reports:generate',
          'reports:schedule',
        ];
        // SOC managers can see/manage every user's reports and schedules, use custom cron and CC/BCC.
        if (role === 'SOC Manager') perms.push('reports:manage');
      }

      const { rows } = await client.query(
        `INSERT INTO roles(name)
         VALUES($1)
         ON CONFLICT(name)
         DO UPDATE SET name = EXCLUDED.name
         RETURNING id`,
        [role]
      );

      const roleId = rows[0].id;

      await client.query(
        `DELETE FROM role_permissions WHERE role_id = $1`,
        [roleId]
      );

      for (const key of perms) {
        await client.query(
          `INSERT INTO role_permissions(role_id, permission_id)
           SELECT $1, id FROM permissions WHERE key = $2
           ON CONFLICT DO NOTHING`,
          [roleId, key]
        );
      }

      await client.query(
        `UPDATE roles SET permissions = $1::jsonb WHERE id = $2`,
        [JSON.stringify(perms), roleId]
      );
    }

    await client.query('COMMIT');

    console.log('Database migrations completed successfully.');
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Database migration failed:', error);
    throw error;
  } finally {
    client.release();
  }
}

// Audit logging
export async function audit(user, action, detail = {}) {
  await pool.query(
    `INSERT INTO audit_logs(user_id, username, action, detail)
     VALUES($1, $2, $3, $4)`,
    [
      user?.id || null,
      user?.username || 'system',
      action,
      JSON.stringify(detail),
    ]
  );
}

// Test database connection
export async function testConnection() {
  const result = await pool.query('SELECT NOW() AS current_time');

  console.log('Supabase PostgreSQL connected:', result.rows[0].current_time);

  return true;
}

// Graceful shutdown
export async function closeDatabase() {
  await pool.end();
  console.log('Database connection closed.');
}
