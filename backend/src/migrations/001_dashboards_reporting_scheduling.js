// Extends the baseline schema created by migrate() in config/db.js.
// Existing tables are reused rather than duplicated:
//   saved_dashboards       -> dashboards
//   report_configurations  -> report templates
//   report_history         -> report execution/file history
//   incidents / incident_comments -> investigations / investigation notes
export default {
  version: '001',
  description: 'Dashboard widgets, report templates/history, persistent report scheduling, email delivery tracking',
  up: `
    -- Dashboards -------------------------------------------------------------
    ALTER TABLE saved_dashboards ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
    ALTER TABLE saved_dashboards ADD COLUMN IF NOT EXISTS is_default BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE saved_dashboards ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE saved_dashboards ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
    CREATE INDEX IF NOT EXISTS saved_dashboards_user_idx ON saved_dashboards(user_id);
    CREATE UNIQUE INDEX IF NOT EXISTS saved_dashboards_one_default_uq ON saved_dashboards(user_id) WHERE is_default;

    CREATE TABLE IF NOT EXISTS dashboard_widgets (
      id BIGSERIAL PRIMARY KEY,
      dashboard_id BIGINT NOT NULL REFERENCES saved_dashboards(id) ON DELETE CASCADE,
      widget_type TEXT NOT NULL,
      title TEXT,
      position INTEGER NOT NULL DEFAULT 0,
      width INTEGER NOT NULL DEFAULT 1 CHECK (width BETWEEN 1 AND 4),
      height INTEGER NOT NULL DEFAULT 1 CHECK (height BETWEEN 1 AND 3),
      config JSONB NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS dashboard_widgets_dashboard_idx ON dashboard_widgets(dashboard_id, position);

    -- Report templates --------------------------------------------------------
    ALTER TABLE report_configurations ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
    ALTER TABLE report_configurations ADD COLUMN IF NOT EXISTS format TEXT NOT NULL DEFAULT 'pdf';
    ALTER TABLE report_configurations ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE report_configurations ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
    CREATE INDEX IF NOT EXISTS report_configurations_created_by_idx ON report_configurations(created_by);

    -- Report schedules ---------------------------------------------------------
    CREATE TABLE IF NOT EXISTS report_schedules (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      report_type TEXT NOT NULL,
      report_config JSONB NOT NULL DEFAULT '{}',
      format TEXT NOT NULL CHECK (format IN ('pdf', 'xlsx', 'csv')),
      frequency TEXT NOT NULL CHECK (frequency IN ('daily', 'weekly', 'monthly', 'cron')),
      cron_expression TEXT,
      start_date DATE NOT NULL,
      start_time TIME NOT NULL,
      timezone TEXT NOT NULL DEFAULT 'UTC',
      end_date DATE,
      recipients JSONB NOT NULL DEFAULT '[]',
      cc JSONB NOT NULL DEFAULT '[]',
      bcc JSONB NOT NULL DEFAULT '[]',
      email_subject TEXT NOT NULL,
      email_message TEXT NOT NULL DEFAULT '',
      delivery_method TEXT NOT NULL DEFAULT 'attachment' CHECK (delivery_method IN ('attachment', 'link')),
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed')),
      next_run_at TIMESTAMPTZ,
      last_run_at TIMESTAMPTZ,
      last_status TEXT,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS report_schedules_due_idx ON report_schedules(status, next_run_at);
    CREATE INDEX IF NOT EXISTS report_schedules_created_by_idx ON report_schedules(created_by);

    -- Report history (generated files) -------------------------------------
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS name TEXT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS report_type TEXT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS generated_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS schedule_id BIGINT REFERENCES report_schedules(id) ON DELETE SET NULL;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual';
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS start_date TIMESTAMPTZ;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS end_date TIMESTAMPTZ;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS format TEXT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS filters JSONB NOT NULL DEFAULT '{}';
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS columns JSONB NOT NULL DEFAULT '[]';
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS storage_backend TEXT NOT NULL DEFAULT 'local';
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS file_name TEXT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS file_size BIGINT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS row_count INTEGER;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS error TEXT;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
    ALTER TABLE report_history ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;
    CREATE INDEX IF NOT EXISTS report_history_created_idx ON report_history(created_at DESC);
    CREATE INDEX IF NOT EXISTS report_history_generated_by_idx ON report_history(generated_by);
    CREATE INDEX IF NOT EXISTS report_history_type_status_idx ON report_history(report_type, status);
    CREATE INDEX IF NOT EXISTS report_history_schedule_idx ON report_history(schedule_id);

    -- Schedule executions (persistent job queue) ---------------------------
    CREATE TABLE IF NOT EXISTS report_execution_history (
      id BIGSERIAL PRIMARY KEY,
      schedule_id BIGINT REFERENCES report_schedules(id) ON DELETE SET NULL,
      schedule_name TEXT NOT NULL,
      scheduled_for TIMESTAMPTZ NOT NULL,
      trigger TEXT NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
      status TEXT NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued', 'running', 'retrying', 'completed', 'failed', 'email_failed')),
      stage TEXT NOT NULL DEFAULT 'generate' CHECK (stage IN ('generate', 'email', 'done')),
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 3,
      next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      locked_by TEXT,
      locked_at TIMESTAMPTZ,
      report_history_id BIGINT REFERENCES report_history(id) ON DELETE SET NULL,
      error TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      -- Prevents duplicate executions of the same scheduled occurrence across backend instances.
      UNIQUE (schedule_id, scheduled_for)
    );
    CREATE INDEX IF NOT EXISTS report_execution_pending_idx ON report_execution_history(status, next_attempt_at);
    CREATE INDEX IF NOT EXISTS report_execution_schedule_idx ON report_execution_history(schedule_id, created_at DESC);

    -- Email delivery tracking -----------------------------------------------
    CREATE TABLE IF NOT EXISTS email_delivery_history (
      id BIGSERIAL PRIMARY KEY,
      execution_id BIGINT REFERENCES report_execution_history(id) ON DELETE CASCADE,
      schedule_id BIGINT REFERENCES report_schedules(id) ON DELETE SET NULL,
      report_history_id BIGINT REFERENCES report_history(id) ON DELETE SET NULL,
      recipients JSONB NOT NULL DEFAULT '[]',
      cc JSONB NOT NULL DEFAULT '[]',
      bcc JSONB NOT NULL DEFAULT '[]',
      subject TEXT NOT NULL,
      delivery_method TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('sent', 'failed')),
      attempt INTEGER NOT NULL DEFAULT 1,
      message_id TEXT,
      error TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS email_delivery_execution_idx ON email_delivery_history(execution_id);
    CREATE INDEX IF NOT EXISTS email_delivery_created_idx ON email_delivery_history(created_at DESC);

    -- Investigations (incidents) and audit lookups -------------------------
    CREATE INDEX IF NOT EXISTS incident_comments_incident_idx ON incident_comments(incident_id, created_at);
    CREATE INDEX IF NOT EXISTS audit_logs_user_idx ON audit_logs(user_id);
  `,
};
