import { config } from './src/config/index.js';
import { pool, migrate } from './src/config/db.js';
import { runMigrations } from './src/migrations/index.js';
import { startReportScheduler, stopReportScheduler } from './src/schedulers/report.scheduler.js';
import app from './app.js';

const server = app.listen(config.port, () => console.log(`SIEM API listening on ${config.port}`));

async function initializeDatabase() {
  try {
    if (config.usingSupabase) console.log('Connecting to Supabase PostgreSQL...');
    await pool.query('SELECT NOW()');
    if (config.usingSupabase) console.log('Supabase PostgreSQL connection successful.');
    await migrate();
    await runMigrations();
    console.log('PostgreSQL schema is ready.');
    startReportScheduler();
  } catch (error) {
    console.error('Database initialization failed:', {
      message: error.message,
      code: error.code,
      detail: error.detail,
      hint: error.hint,
    });
    setTimeout(initializeDatabase, 15_000).unref();
  }
}

initializeDatabase();

async function shutdown(signal) {
  console.log(`${signal} received, shutting down.`);
  await stopReportScheduler();
  server.close(() => pool.end().finally(() => process.exit(0)));
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));
