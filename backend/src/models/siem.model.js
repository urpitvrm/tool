import { pool } from '../config/db.js';

export async function listIncidents() {
  return (await pool.query('SELECT * FROM incidents ORDER BY created_at DESC LIMIT 500')).rows;
}

export async function createIncident({ title, severity, description, assignedTo, userId }) {
  const { rows } = await pool.query(
    'INSERT INTO incidents(title,severity,description,assigned_to,created_by) VALUES($1,$2,$3,$4,$5) RETURNING *',
    [title, severity, description, assignedTo || null, userId],
  );
  return rows[0];
}

export async function updateIncidentStatus(id, status) {
  const { rows } = await pool.query('UPDATE incidents SET status=$1,updated_at=now() WHERE id=$2 RETURNING *', [status, id]);
  return rows[0] || null;
}

export async function addIncidentComment(incidentId, userId, body) {
  const { rows } = await pool.query(
    'INSERT INTO incident_comments(incident_id,user_id,body) VALUES($1,$2,$3) RETURNING *', [incidentId, userId, body],
  );
  return rows[0];
}

export async function listAuditLogs(page, size) {
  return (await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC OFFSET $1 LIMIT $2', [(page - 1) * size, size])).rows;
}

export async function upsertSavedSearch(userId, name, query, module = 'events') {
  const { rows } = await pool.query(
    `INSERT INTO saved_searches(user_id,module,name,query) VALUES($1,$2,$3,$4)
     ON CONFLICT(user_id,module,name) DO UPDATE SET query=EXCLUDED.query, updated_at=now() RETURNING *`,
    [userId, module, name, JSON.stringify(query)],
  );
  return rows[0];
}

export async function listSavedSearches(userId, module) {
  return (await pool.query(
    'SELECT * FROM saved_searches WHERE user_id=$1 AND ($2::text IS NULL OR module=$2) ORDER BY name', [userId, module || null],
  )).rows;
}

export async function deleteSavedSearch(userId, id) {
  const { rowCount } = await pool.query('DELETE FROM saved_searches WHERE user_id=$1 AND id=$2', [userId, id]);
  return rowCount > 0;
}

export async function getTablePreference(userId, module, tableKey) {
  const { rows } = await pool.query(
    'SELECT columns, page_size, updated_at FROM user_table_preferences WHERE user_id=$1 AND module=$2 AND table_key=$3', [userId, module, tableKey],
  );
  return rows[0] || null;
}

export async function saveTablePreference(userId, module, tableKey, columns, pageSize) {
  const { rows } = await pool.query(
    `INSERT INTO user_table_preferences(user_id, module, table_key, columns, page_size) VALUES($1,$2,$3,$4,$5)
     ON CONFLICT(user_id, module, table_key) DO UPDATE SET columns=EXCLUDED.columns, page_size=EXCLUDED.page_size, updated_at=now()
     RETURNING columns, page_size, updated_at`,
    [userId, module, tableKey, JSON.stringify(columns), pageSize ?? null],
  );
  return rows[0];
}

export async function deleteTablePreference(userId, module, tableKey) {
  await pool.query('DELETE FROM user_table_preferences WHERE user_id=$1 AND module=$2 AND table_key=$3', [userId, module, tableKey]);
}

export async function listNotificationRules() {
  return (await pool.query('SELECT id,name,condition,channel_id,enabled FROM notification_rules ORDER BY id')).rows;
}

export async function createNotificationRule({ name, condition, channelId, enabled }) {
  const { rows } = await pool.query(
    'INSERT INTO notification_rules(name,condition,channel_id,enabled) VALUES($1,$2,$3,$4) RETURNING *',
    [name, JSON.stringify(condition), channelId || null, enabled],
  );
  return rows[0];
}

export async function listSettings() {
  return (await pool.query('SELECT key,value,updated_at FROM application_settings ORDER BY key')).rows;
}

export async function upsertSetting(key, value) {
  await pool.query('INSERT INTO application_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()',
    [key, JSON.stringify(value)]);
}
