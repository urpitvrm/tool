import { pool } from '../config/db.js';
import m001 from './001_dashboards_reporting_scheduling.js';
import m002 from './002_table_preferences_and_module_searches.js';
import m003 from './003_authentication.js';
import m004 from './004_login_history_device.js';

// Ordered, append-only list. Never edit a migration that has shipped; add a new one instead.
const migrations = [m001, m002, m003, m004];

// Arbitrary constant used for a cluster-wide advisory lock so that only one backend
// instance applies migrations at a time.
const MIGRATION_LOCK_KEY = 74_210_001;

export async function runMigrations() {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [MIGRATION_LOCK_KEY]);
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      version TEXT PRIMARY KEY,
      description TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    const { rows } = await client.query('SELECT version FROM schema_migrations');
    const applied = new Set(rows.map((row) => row.version));

    for (const migration of migrations) {
      if (applied.has(migration.version)) continue;
      console.log(`Applying migration ${migration.version}: ${migration.description}`);
      await client.query('BEGIN');
      try {
        await client.query(migration.up);
        await client.query('INSERT INTO schema_migrations(version, description) VALUES($1, $2)', [migration.version, migration.description]);
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [MIGRATION_LOCK_KEY]).catch(() => {});
    client.release();
  }
}
