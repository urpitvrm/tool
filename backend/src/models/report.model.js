import { pool } from '../config/db.js';

const HISTORY_COLUMNS = `h.id, h.name, h.report_type, h.status, h.format, h.source, h.start_date, h.end_date,
  h.filters, h.columns, h.file_name, h.file_size, h.row_count, h.error, h.created_at, h.started_at, h.completed_at,
  h.generated_by, u.username AS generated_by_username, h.schedule_id, h.configuration_id,
  (h.artifact_path IS NOT NULL) AS downloadable`;

export async function insertHistory(record) {
  const { rows } = await pool.query(
    `INSERT INTO report_history(name, report_type, status, format, source, start_date, end_date, filters, columns,
       generated_by, schedule_id, configuration_id, started_at)
     VALUES($1, $2, 'running', $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
     RETURNING id`,
    [record.name, record.report_type, record.format, record.source || 'manual', record.start_date, record.end_date,
      JSON.stringify(record.filters || {}), JSON.stringify(record.columns || []), record.generated_by || null,
      record.schedule_id || null, record.configuration_id || null],
  );
  return rows[0].id;
}

export async function completeHistory(id, { artifactPath, storageBackend, fileName, fileSize, rowCount }) {
  await pool.query(
    `UPDATE report_history SET status = 'completed', artifact_path = $2, storage_backend = $3, file_name = $4,
       file_size = $5, row_count = $6, completed_at = now(), error = NULL WHERE id = $1`,
    [id, artifactPath, storageBackend, fileName, fileSize, rowCount],
  );
}

export async function failHistory(id, error) {
  await pool.query("UPDATE report_history SET status = 'failed', error = $2, completed_at = now() WHERE id = $1", [id, String(error).slice(0, 1000)]);
}

export async function findHistory(id) {
  const { rows } = await pool.query(
    `SELECT ${HISTORY_COLUMNS}, h.artifact_path, h.storage_backend
     FROM report_history h LEFT JOIN users u ON u.id = h.generated_by WHERE h.id = $1`, [id],
  );
  return rows[0] || null;
}

/** Paged history. `ownerId` restricts results to one user's reports (null = all). */
export async function listHistory({ ownerId = null, q, reportType, status, userId, format, page = 1, size = 25 }) {
  const where = [];
  const params = [];
  const add = (sql, value) => { params.push(value); where.push(sql.replaceAll('?', `$${params.length}`)); };
  if (ownerId != null) add('h.generated_by = ?', ownerId);
  if (userId) add('h.generated_by = ?', userId);
  if (reportType) add('h.report_type = ?', reportType);
  if (status) add('h.status = ?', status);
  if (format) add('h.format = ?', format);
  if (q) add('(h.name ILIKE ? OR h.report_type ILIKE ?)', `%${q}%`);
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const countParams = [...params];
  params.push((page - 1) * size, size);
  const [{ rows }, count] = await Promise.all([
    pool.query(
      `SELECT ${HISTORY_COLUMNS} FROM report_history h LEFT JOIN users u ON u.id = h.generated_by ${clause}
       ORDER BY h.created_at DESC, h.id DESC OFFSET $${params.length - 1} LIMIT $${params.length}`, params,
    ),
    pool.query(`SELECT COUNT(*)::int AS total FROM report_history h ${clause}`, countParams),
  ]);
  return { total: count.rows[0].total, page, size, items: rows };
}

export async function deleteHistory(id) {
  const { rows } = await pool.query('DELETE FROM report_history WHERE id = $1 RETURNING artifact_path', [id]);
  return rows[0] || null;
}

/** Reports past retention: returns file keys and clears them from the history rows. */
export async function expireHistory(retentionDays) {
  const { rows } = await pool.query(
    `WITH expired AS (
       SELECT id, artifact_path FROM report_history
       WHERE artifact_path IS NOT NULL AND created_at < now() - make_interval(days => $1)
       FOR UPDATE SKIP LOCKED
     )
     UPDATE report_history h SET artifact_path = NULL, status = 'expired'
     FROM expired e WHERE h.id = e.id
     RETURNING e.id, e.artifact_path AS old_path`,
    [retentionDays],
  );
  return rows;
}

// ---- Templates (report_configurations) -----------------------------------

const TEMPLATE_COLUMNS = `c.id, c.name, c.description, c.report_type, c.format, c.options, c.created_by,
  u.username AS created_by_username, c.created_at, c.updated_at`;

export async function listTemplates(ownerId = null) {
  const { rows } = await pool.query(
    `SELECT ${TEMPLATE_COLUMNS} FROM report_configurations c LEFT JOIN users u ON u.id = c.created_by
     WHERE ($1::int IS NULL OR c.created_by = $1) ORDER BY c.name`, [ownerId],
  );
  return rows;
}

export async function findTemplate(id) {
  const { rows } = await pool.query(
    `SELECT ${TEMPLATE_COLUMNS} FROM report_configurations c LEFT JOIN users u ON u.id = c.created_by WHERE c.id = $1`, [id],
  );
  return rows[0] || null;
}

export async function insertTemplate({ name, description, report_type: reportType, format, options }, userId) {
  const { rows } = await pool.query(
    `INSERT INTO report_configurations(name, description, report_type, format, options, created_by)
     VALUES($1, $2, $3, $4, $5, $6) RETURNING id`,
    [name, description || '', reportType, format, JSON.stringify(options || {}), userId],
  );
  return findTemplate(rows[0].id);
}

export async function updateTemplate(id, { name, description, report_type: reportType, format, options }) {
  await pool.query(
    `UPDATE report_configurations SET name = $2, description = $3, report_type = $4, format = $5, options = $6, updated_at = now()
     WHERE id = $1`,
    [id, name, description || '', reportType, format, JSON.stringify(options || {})],
  );
  return findTemplate(id);
}

export async function deleteTemplate(id) {
  const { rowCount } = await pool.query('DELETE FROM report_configurations WHERE id = $1', [id]);
  return rowCount > 0;
}
