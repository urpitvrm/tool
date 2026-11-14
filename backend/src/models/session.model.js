import { pool } from '../config/db.js';

const COLUMNS = 'id, user_id, device_information, ip_address, user_agent, remember, created_at, last_used_at, expires_at, revoked_at, revoke_reason';

export async function createSession({ userId, refreshHash, expiresAt, remember, ip, userAgent, device }) {
  const { rows } = await pool.query(
    `INSERT INTO user_sessions(user_id, refresh_token_hash, expires_at, remember, ip_address, user_agent, device_information, last_used_at)
     VALUES($1, $2, $3, $4, $5, $6, $7, now()) RETURNING ${COLUMNS}`,
    [userId, refreshHash, expiresAt, remember, ip, userAgent, device],
  );
  return rows[0];
}

/** Active (not revoked, not expired) session, used by the auth middleware on every request. */
export async function findActiveSession(id, userId) {
  const { rows } = await pool.query(
    `SELECT ${COLUMNS} FROM user_sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()`,
    [id, userId],
  );
  return rows[0] || null;
}

/**
 * Rotate a refresh token atomically: only succeeds for the current token of an active session.
 * Returns the session, or null if the token is not current.
 */
export async function rotateRefreshToken(currentHash, nextHash) {
  const { rows } = await pool.query(
    `UPDATE user_sessions SET previous_token_hash = refresh_token_hash, refresh_token_hash = $2, last_used_at = now()
     WHERE refresh_token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
     RETURNING ${COLUMNS}`,
    [currentHash, nextHash],
  );
  return rows[0] || null;
}

/** A presented token that was already rotated away indicates theft/replay. */
export async function findByPreviousToken(hash) {
  const { rows } = await pool.query(`SELECT ${COLUMNS} FROM user_sessions WHERE previous_token_hash = $1`, [hash]);
  return rows[0] || null;
}

export async function findByRefreshToken(hash) {
  const { rows } = await pool.query(`SELECT ${COLUMNS} FROM user_sessions WHERE refresh_token_hash = $1`, [hash]);
  return rows[0] || null;
}

export async function revokeSession(id, reason, userId = null) {
  const { rowCount } = await pool.query(
    `UPDATE user_sessions SET revoked_at = now(), revoke_reason = $2
     WHERE id = $1 AND revoked_at IS NULL AND ($3::int IS NULL OR user_id = $3)`,
    [id, reason, userId],
  );
  return rowCount > 0;
}

export async function revokeAllSessions(userId, reason, exceptSessionId = null, db = pool) {
  const { rowCount } = await db.query(
    `UPDATE user_sessions SET revoked_at = now(), revoke_reason = $2
     WHERE user_id = $1 AND revoked_at IS NULL AND ($3::int IS NULL OR id <> $3)`,
    [userId, reason, exceptSessionId],
  );
  return rowCount;
}

export async function listSessions(userId) {
  const { rows } = await pool.query(
    `SELECT ${COLUMNS} FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() ORDER BY last_used_at DESC NULLS LAST`,
    [userId],
  );
  return rows;
}

export async function deleteStale(days = 7) {
  const { rowCount } = await pool.query(
    'DELETE FROM user_sessions WHERE COALESCE(revoked_at, expires_at) < now() - make_interval(days => $1)',
    [days],
  );
  return rowCount;
}

// ---- Login history -----------------------------------------------------------------------------

export async function recordLoginEvent({ userId = null, email = null, identifier = null, ip, userAgent, device = null, status, reason = null }) {
  await pool.query(
    `INSERT INTO login_history(user_id, email, identifier, ip_address, user_agent, device_information, login_status, failure_reason)
     VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
    [userId, email, identifier ? String(identifier).slice(0, 200) : null, ip, userAgent, device, status, reason],
  );
}

export async function listLoginHistory(userId, limit = 50) {
  const { rows } = await pool.query(
    `SELECT id, user_id, email, identifier, ip_address, user_agent, device_information, login_status, failure_reason, created_at
     FROM login_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [userId, limit],
  );
  return rows;
}

/** Has this user signed in successfully from this IP with this device family in the last `days` days? */
export async function isKnownDevice(userId, ip, device, days = 90) {
  const { rows } = await pool.query(
    `SELECT 1 FROM login_history WHERE user_id = $1 AND login_status = 'success'
     AND created_at > now() - make_interval(days => $4) AND ip_address = $2 AND device_information = $3 LIMIT 1`,
    [userId, ip, device, days],
  );
  return rows.length > 0;
}

export async function hasPriorSuccess(userId) {
  const { rows } = await pool.query("SELECT 1 FROM login_history WHERE user_id = $1 AND login_status = 'success' LIMIT 1", [userId]);
  return rows.length > 0;
}

export async function deleteOldLoginHistory(days) {
  const { rowCount } = await pool.query('DELETE FROM login_history WHERE created_at < now() - make_interval(days => $1)', [days]);
  return rowCount;
}
