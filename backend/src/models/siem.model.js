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

export async function upsertSavedSearch(userId, name, query) {
  const { rows } = await pool.query(
    'INSERT INTO saved_searches(user_id,name,query) VALUES($1,$2,$3) ON CONFLICT(user_id,name) DO UPDATE SET query=EXCLUDED.query RETURNING *',
    [userId, name, JSON.stringify(query)],
  );
  return rows[0];
}

export async function listSavedSearches(userId) {
  return (await pool.query('SELECT * FROM saved_searches WHERE user_id=$1 ORDER BY name', [userId])).rows;
}

export async function listDashboards(userId) {
  return (await pool.query('SELECT id,name,layout FROM saved_dashboards WHERE user_id=$1 ORDER BY name', [userId])).rows;
}

export async function createDashboard(userId, name, layout) {
  const { rows } = await pool.query('INSERT INTO saved_dashboards(user_id,name,layout) VALUES($1,$2,$3) RETURNING *',
    [userId, name, JSON.stringify(layout)]);
  return rows[0];
}

export async function listReportHistory() {
  return (await pool.query('SELECT id,configuration_id,status,created_at FROM report_history ORDER BY created_at DESC LIMIT 200')).rows;
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
