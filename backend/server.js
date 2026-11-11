import { config } from './src/config/index.js';
import { pool, migrate } from './src/config/db.js';
import app from './app.js';

app.listen(config.port, () => console.log(`SIEM API listening on ${config.port}`));

async function initializeDatabase() {
  try {
    if (config.usingSupabase) console.log('Connecting to Supabase PostgreSQL...');
    await pool.query('SELECT NOW()');
    if (config.usingSupabase) console.log('Supabase PostgreSQL connection successful.');
    await migrate();
    console.log('PostgreSQL schema is ready.');
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
