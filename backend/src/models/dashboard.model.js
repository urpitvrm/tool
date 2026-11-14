import { pool } from '../config/db.js';

const WIDGETS_JSON = `COALESCE((
  SELECT json_agg(json_build_object(
    'id', w.id, 'widget_type', w.widget_type, 'title', w.title, 'position', w.position,
    'width', w.width, 'height', w.height, 'config', w.config
  ) ORDER BY w.position, w.id)
  FROM dashboard_widgets w WHERE w.dashboard_id = d.id
), '[]'::json) AS widgets`;

const COLUMNS = `d.id, d.name, d.description, d.layout, d.is_default, d.created_at, d.updated_at, ${WIDGETS_JSON}`;

export async function listDashboards(userId) {
  const { rows } = await pool.query(
    `SELECT ${COLUMNS} FROM saved_dashboards d WHERE d.user_id = $1 ORDER BY d.is_default DESC, d.name`, [userId],
  );
  return rows;
}

export async function findDashboard(userId, id) {
  const { rows } = await pool.query(`SELECT ${COLUMNS} FROM saved_dashboards d WHERE d.user_id = $1 AND d.id = $2`, [userId, id]);
  return rows[0] || null;
}

async function replaceWidgets(client, dashboardId, widgets) {
  await client.query('DELETE FROM dashboard_widgets WHERE dashboard_id = $1', [dashboardId]);
  for (const [index, widget] of widgets.entries()) {
    await client.query(
      `INSERT INTO dashboard_widgets(dashboard_id, widget_type, title, position, width, height, config)
       VALUES($1, $2, $3, $4, $5, $6, $7)`,
      [dashboardId, widget.widget_type, widget.title || null, index, widget.width || 1, widget.height || 1, JSON.stringify(widget.config || {})],
    );
  }
}

async function inTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function createDashboard(userId, { name, description = '', layout = {}, is_default = false, widgets }) {
  const id = await inTransaction(async (client) => {
    if (is_default) await client.query('UPDATE saved_dashboards SET is_default = false WHERE user_id = $1', [userId]);
    const { rows } = await client.query(
      `INSERT INTO saved_dashboards(user_id, name, description, layout, is_default)
       VALUES($1, $2, $3, $4, $5) RETURNING id`,
      [userId, name, description, JSON.stringify(layout), is_default],
    );
    if (Array.isArray(widgets)) await replaceWidgets(client, rows[0].id, widgets);
    return rows[0].id;
  });
  return findDashboard(userId, id);
}

export async function updateDashboard(userId, id, { name, description, layout, is_default, widgets }) {
  const updated = await inTransaction(async (client) => {
    const { rows } = await client.query('SELECT id FROM saved_dashboards WHERE id = $1 AND user_id = $2 FOR UPDATE', [id, userId]);
    if (!rows.length) return false;
    if (is_default) await client.query('UPDATE saved_dashboards SET is_default = false WHERE user_id = $1 AND id <> $2', [userId, id]);
    await client.query(
      `UPDATE saved_dashboards SET
         name = COALESCE($3, name),
         description = COALESCE($4, description),
         layout = COALESCE($5, layout),
         is_default = COALESCE($6, is_default),
         updated_at = now()
       WHERE id = $1 AND user_id = $2`,
      [id, userId, name ?? null, description ?? null, layout ? JSON.stringify(layout) : null, is_default ?? null],
    );
    if (Array.isArray(widgets)) await replaceWidgets(client, id, widgets);
    return true;
  });
  return updated ? findDashboard(userId, id) : null;
}

export async function deleteDashboard(userId, id) {
  const { rowCount } = await pool.query('DELETE FROM saved_dashboards WHERE id = $1 AND user_id = $2', [id, userId]);
  return rowCount > 0;
}
