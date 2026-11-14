import { pool } from '../config/db.js';

const SCHEDULE_COLUMNS = `s.id, s.name, s.report_type, s.report_config, s.format, s.frequency, s.cron_expression,
  s.start_date, to_char(s.start_time, 'HH24:MI') AS start_time, s.timezone, s.end_date, s.recipients, s.cc, s.bcc,
  s.email_subject, s.email_message, s.delivery_method, s.status, s.next_run_at, s.last_run_at, s.last_status,
  s.created_by, u.username AS created_by_username, s.created_at, s.updated_at`;

const FIELDS = ['name', 'report_type', 'report_config', 'format', 'frequency', 'cron_expression', 'start_date', 'start_time',
  'timezone', 'end_date', 'recipients', 'cc', 'bcc', 'email_subject', 'email_message', 'delivery_method', 'status', 'next_run_at'];
const JSON_FIELDS = new Set(['report_config', 'recipients', 'cc', 'bcc']);
const serialize = (field, value) => (JSON_FIELDS.has(field) ? JSON.stringify(value ?? (field === 'report_config' ? {} : [])) : value ?? null);

export async function findSchedule(id, db = pool) {
  const { rows } = await db.query(`SELECT ${SCHEDULE_COLUMNS} FROM report_schedules s LEFT JOIN users u ON u.id = s.created_by WHERE s.id = $1`, [id]);
  return rows[0] || null;
}

export async function listSchedules(ownerId = null) {
  const { rows } = await pool.query(
    `SELECT ${SCHEDULE_COLUMNS},
       (SELECT json_build_object('id', e.id, 'status', e.status, 'scheduled_for', e.scheduled_for, 'completed_at', e.completed_at, 'error', e.error)
          FROM report_execution_history e WHERE e.schedule_id = s.id ORDER BY e.created_at DESC LIMIT 1) AS last_execution
     FROM report_schedules s LEFT JOIN users u ON u.id = s.created_by
     WHERE ($1::int IS NULL OR s.created_by = $1)
     ORDER BY s.status = 'active' DESC, s.next_run_at NULLS LAST, s.name`, [ownerId],
  );
  return rows;
}

export async function insertSchedule(data, userId) {
  const columns = [...FIELDS, 'created_by'];
  const values = [...FIELDS.map((field) => serialize(field, data[field])), userId];
  const { rows } = await pool.query(
    `INSERT INTO report_schedules(${columns.join(', ')}) VALUES(${columns.map((_, index) => `$${index + 1}`).join(', ')}) RETURNING id`, values,
  );
  return findSchedule(rows[0].id);
}

export async function updateSchedule(id, data) {
  const fields = FIELDS.filter((field) => field in data);
  if (!fields.length) return findSchedule(id);
  await pool.query(
    `UPDATE report_schedules SET ${fields.map((field, index) => `${field} = $${index + 2}`).join(', ')}, updated_at = now() WHERE id = $1`,
    [id, ...fields.map((field) => serialize(field, data[field]))],
  );
  return findSchedule(id);
}

export async function deleteSchedule(id) {
  const { rowCount } = await pool.query('DELETE FROM report_schedules WHERE id = $1', [id]);
  return rowCount > 0;
}

// ---- Scheduler: due schedules → queued executions ------------------------

/** Lock up to `limit` due schedules for this transaction; other instances skip them. */
export async function lockDueSchedules(client, limit = 20) {
  const { rows } = await client.query(
    `SELECT id, name, frequency, cron_expression, start_date, to_char(start_time, 'HH24:MI') AS start_time, timezone, end_date, next_run_at
     FROM report_schedules WHERE status = 'active' AND next_run_at IS NOT NULL AND next_run_at <= now()
     ORDER BY next_run_at FOR UPDATE SKIP LOCKED LIMIT $1`, [limit],
  );
  return rows;
}

/** Idempotently enqueue one occurrence. Returns the execution id, or null if it already exists. */
export async function enqueueExecution(db, { scheduleId, scheduleName, scheduledFor, trigger = 'schedule', maxAttempts }) {
  const { rows } = await db.query(
    `INSERT INTO report_execution_history(schedule_id, schedule_name, scheduled_for, trigger, max_attempts)
     VALUES($1, $2, $3, $4, $5) ON CONFLICT (schedule_id, scheduled_for) DO NOTHING RETURNING id`,
    [scheduleId, scheduleName, scheduledFor, trigger, maxAttempts],
  );
  return rows[0]?.id || null;
}

export async function advanceSchedule(db, id, nextRunAt) {
  await db.query(
    `UPDATE report_schedules SET next_run_at = $2, status = CASE WHEN $2::timestamptz IS NULL THEN 'completed' ELSE status END,
       updated_at = now() WHERE id = $1`, [id, nextRunAt],
  );
}

export async function recordScheduleRun(id, status) {
  await pool.query('UPDATE report_schedules SET last_run_at = now(), last_status = $2 WHERE id = $1', [id, status]);
}

// ---- Execution queue ------------------------------------------------------

/** Atomically claim the next runnable execution (including ones abandoned by a crashed worker). */
export async function claimExecution(workerId, staleMinutes) {
  const { rows } = await pool.query(
    `UPDATE report_execution_history e SET status = 'running', locked_by = $1, locked_at = now(),
       attempts = e.attempts + 1, started_at = COALESCE(e.started_at, now())
     WHERE e.id = (
       SELECT id FROM report_execution_history
       WHERE (status IN ('queued', 'retrying') AND next_attempt_at <= now())
          OR (status = 'running' AND locked_at < now() - make_interval(mins => $2))
       ORDER BY next_attempt_at, id
       FOR UPDATE SKIP LOCKED LIMIT 1
     )
     RETURNING e.*`, [workerId, staleMinutes],
  );
  return rows[0] || null;
}

export async function updateExecution(id, fields) {
  const keys = Object.keys(fields);
  await pool.query(
    `UPDATE report_execution_history SET ${keys.map((key, index) => `${key} = $${index + 2}`).join(', ')} WHERE id = $1`,
    [id, ...keys.map((key) => fields[key])],
  );
}

export async function findExecution(id) {
  const { rows } = await pool.query(
    `SELECT e.*, s.created_by FROM report_execution_history e LEFT JOIN report_schedules s ON s.id = e.schedule_id WHERE e.id = $1`, [id],
  );
  return rows[0] || null;
}

export async function listExecutions(scheduleId, page = 1, size = 25) {
  const [{ rows }, count] = await Promise.all([
    pool.query(
      `SELECT e.id, e.schedule_id, e.scheduled_for, e.trigger, e.status, e.stage, e.attempts, e.max_attempts, e.next_attempt_at,
         e.report_history_id, e.error, e.started_at, e.completed_at, e.created_at,
         h.file_name, h.format, h.status AS report_status, (h.artifact_path IS NOT NULL) AS downloadable,
         COALESCE((SELECT json_agg(json_build_object('id', d.id, 'status', d.status, 'attempt', d.attempt, 'recipients', d.recipients,
           'cc', d.cc, 'bcc', d.bcc, 'delivery_method', d.delivery_method, 'message_id', d.message_id, 'error', d.error, 'created_at', d.created_at)
           ORDER BY d.created_at) FROM email_delivery_history d WHERE d.execution_id = e.id), '[]'::json) AS deliveries
       FROM report_execution_history e LEFT JOIN report_history h ON h.id = e.report_history_id
       WHERE e.schedule_id = $1 ORDER BY e.created_at DESC OFFSET $2 LIMIT $3`, [scheduleId, (page - 1) * size, size],
    ),
    pool.query('SELECT COUNT(*)::int AS total FROM report_execution_history WHERE schedule_id = $1', [scheduleId]),
  ]);
  return { total: count.rows[0].total, page, size, items: rows };
}

/** Requeue a failed execution. Keeps the generated report so only the failed stage reruns. */
export async function requeueExecution(id) {
  const { rows } = await pool.query(
    `UPDATE report_execution_history SET status = 'queued', attempts = 0, next_attempt_at = now(), error = NULL,
       locked_by = NULL, locked_at = NULL, completed_at = NULL
     WHERE id = $1 AND status IN ('failed', 'email_failed') RETURNING *`, [id],
  );
  return rows[0] || null;
}

export async function insertEmailDelivery(record) {
  await pool.query(
    `INSERT INTO email_delivery_history(execution_id, schedule_id, report_history_id, recipients, cc, bcc, subject, delivery_method,
       status, attempt, message_id, error)
     VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [record.executionId, record.scheduleId, record.reportHistoryId, JSON.stringify(record.recipients), JSON.stringify(record.cc || []),
      JSON.stringify(record.bcc || []), record.subject, record.deliveryMethod, record.status, record.attempt, record.messageId || null,
      record.error ? String(record.error).slice(0, 1000) : null],
  );
}
