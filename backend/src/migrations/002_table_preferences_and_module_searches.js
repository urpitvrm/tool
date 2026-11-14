// Per-user, per-module table column preferences, and module-scoped saved searches.
export default {
  version: '002',
  description: 'User table column preferences; saved searches scoped by module',
  up: `
    CREATE TABLE IF NOT EXISTS user_table_preferences (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      module TEXT NOT NULL,
      table_key TEXT NOT NULL DEFAULT 'search',
      columns JSONB NOT NULL DEFAULT '[]',
      page_size INTEGER CHECK (page_size BETWEEN 1 AND 200),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, module, table_key)
    );

    -- Existing saved searches came from the Security Events page.
    ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS module TEXT NOT NULL DEFAULT 'events';
    ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE saved_searches DROP CONSTRAINT IF EXISTS saved_searches_user_id_name_key;
    CREATE UNIQUE INDEX IF NOT EXISTS saved_searches_user_module_name_uq ON saved_searches(user_id, module, name);
  `,
};
