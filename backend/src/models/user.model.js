import { pool } from '../config/db.js';

// Columns safe to return to clients (never password hashes).
const PUBLIC = `u.id, u.username, u.full_name, u.email, u.email_verified, u.email_verified_at, u.status, u.role_id, r.name AS role,
  u.failed_login_attempts, u.locked_until, u.last_login_at, u.force_password_change, u.password_changed_at,
  u.disabled, u.created_at, u.updated_at`;

export async function findActiveById(id) {
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.full_name, u.email, u.role_id, r.name AS role, u.force_password_change, u.status
     FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1 AND u.status = 'active'`,
    [id],
  );
  return rows[0] || null;
}

export async function findById(id, db = pool) {
  const { rows } = await db.query(`SELECT ${PUBLIC} FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, [id]);
  return rows[0] || null;
}

/** For credential checks only: includes the password hash. */
export async function findAuthById(id, db = pool) {
  const { rows } = await db.query(`SELECT ${PUBLIC}, u.password_hash FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $1`, [id]);
  return rows[0] || null;
}

/** Username (exact) or email (case-insensitive). */
export async function findAuthByIdentifier(identifier) {
  const { rows } = await pool.query(
    `SELECT ${PUBLIC}, u.password_hash FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.username = $1 OR (u.email IS NOT NULL AND lower(u.email) = lower($1)) LIMIT 1`,
    [identifier],
  );
  return rows[0] || null;
}

export async function findByEmail(email) {
  const { rows } = await pool.query(`SELECT ${PUBLIC} FROM users u JOIN roles r ON r.id = u.role_id WHERE lower(u.email) = lower($1)`, [email]);
  return rows[0] || null;
}

// Retained for existing callers.
export async function findByUsername(username) {
  const { rows } = await pool.query(`SELECT ${PUBLIC}, u.password_hash FROM users u JOIN roles r ON r.id = u.role_id WHERE u.username = $1`, [username]);
  return rows[0] || null;
}

export async function countUsers() {
  const { rows } = await pool.query('SELECT COUNT(*)::int n FROM users');
  return rows[0].n;
}

export async function getBootstrapRoleId() {
  const { rows } = await pool.query("SELECT id FROM roles WHERE name='Super Administrator'");
  return rows[0]?.id;
}

/** Create a user. `passwordHash` is null for invited users. */
export async function insertUser({ username, fullName = '', email = null, passwordHash = null, roleId, status = 'active', emailVerified = false, invitedBy = null }, db = pool) {
  const { rows } = await db.query(
    `INSERT INTO users(username, full_name, email, password_hash, role_id, status, email_verified, email_verified_at, invited_by, password_changed_at)
     VALUES($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 THEN now() END, $8, CASE WHEN $4::text IS NOT NULL THEN now() END)
     RETURNING id, username, role_id`,
    [username, fullName, email, passwordHash, roleId, status, emailVerified, invitedBy],
  );
  if (passwordHash) await db.query('INSERT INTO password_history(user_id, password_hash) VALUES($1, $2)', [rows[0].id, passwordHash]);
  return rows[0];
}

// ---- RBAC --------------------------------------------------------------------------------------

/** Permission keys from the primary role plus any additional roles in user_roles. */
export async function permissionsForUser(userId) {
  const { rows } = await pool.query(
    `SELECT DISTINCT p.key FROM permissions p
     JOIN role_permissions rp ON rp.permission_id = p.id
     WHERE rp.role_id IN (SELECT role_id FROM users WHERE id = $1 UNION SELECT role_id FROM user_roles WHERE user_id = $1)
     ORDER BY p.key`,
    [userId],
  );
  return rows.map((row) => row.key);
}

export async function rolesForUser(userId) {
  const { rows } = await pool.query(
    `SELECT r.id, r.name, (r.id = u.role_id) AS primary FROM users u
     JOIN roles r ON r.id = u.role_id OR r.id IN (SELECT role_id FROM user_roles WHERE user_id = u.id)
     WHERE u.id = $1 ORDER BY (r.id = u.role_id) DESC, r.name`,
    [userId],
  );
  return rows;
}

/** Permission check for a user object or id (covers all assigned roles). */
export async function userHasPermission(userOrId, permissionKey) {
  const id = typeof userOrId === 'object' ? userOrId.id : userOrId;
  if (typeof userOrId === 'object' && Array.isArray(userOrId.permissions)) return userOrId.permissions.includes(permissionKey);
  return (await permissionsForUser(id)).includes(permissionKey);
}

// Retained: single-role check by role id.
export async function hasPermission(roleId, permissionKey) {
  const { rows } = await pool.query(
    'SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=$1 AND p.key=$2',
    [roleId, permissionKey],
  );
  return rows.length > 0;
}

export async function setAdditionalRoles(userId, roleIds, db = pool) {
  await db.query('DELETE FROM user_roles WHERE user_id = $1', [userId]);
  for (const roleId of roleIds) await db.query('INSERT INTO user_roles(user_id, role_id) VALUES($1, $2) ON CONFLICT DO NOTHING', [userId, roleId]);
}

// ---- Account state -----------------------------------------------------------------------------

/** Atomically count a failed attempt; locks the account when the threshold is reached. */
export async function recordFailedLogin(userId, maxAttempts, lockMinutes) {
  const { rows } = await pool.query(
    `UPDATE users SET
       failed_login_attempts = failed_login_attempts + 1,
       locked_until = CASE WHEN failed_login_attempts + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END
     WHERE id = $1
     RETURNING failed_login_attempts, locked_until, (failed_login_attempts >= $2) AS locked`,
    [userId, maxAttempts, lockMinutes],
  );
  return rows[0];
}

export async function recordSuccessfulLogin(userId) {
  await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1', [userId]);
}

export async function unlockUser(userId) {
  await pool.query('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1', [userId]);
}

export async function setStatus(userId, status, db = pool) {
  await db.query('UPDATE users SET status = $2 WHERE id = $1', [userId, status]);
}

export async function markEmailVerified(userId, db = pool) {
  await db.query('UPDATE users SET email_verified = true, email_verified_at = now() WHERE id = $1', [userId]);
}

export async function setForcePasswordChange(userId, value) {
  await pool.query('UPDATE users SET force_password_change = $2 WHERE id = $1', [userId, value]);
}

/** Store a new password, record it in history and clear lock/forced-change state. */
export async function setPassword(userId, passwordHash, db = pool) {
  await db.query(
    `UPDATE users SET password_hash = $2, password_changed_at = now(), force_password_change = false,
       failed_login_attempts = 0, locked_until = NULL WHERE id = $1`,
    [userId, passwordHash],
  );
  await db.query('INSERT INTO password_history(user_id, password_hash) VALUES($1, $2)', [userId, passwordHash]);
}

export async function recentPasswordHashes(userId, limit) {
  const { rows } = await pool.query('SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2', [userId, limit]);
  return rows.map((row) => row.password_hash);
}

export async function updateProfile(userId, { fullName, email, roleId }, db = pool) {
  await db.query(
    `UPDATE users SET
       full_name = COALESCE($2, full_name),
       email_verified = CASE WHEN $3::text IS NOT NULL AND lower($3) IS DISTINCT FROM lower(email) THEN false ELSE email_verified END,
       email_verified_at = CASE WHEN $3::text IS NOT NULL AND lower($3) IS DISTINCT FROM lower(email) THEN NULL ELSE email_verified_at END,
       email = COALESCE($3, email),
       role_id = COALESCE($4, role_id)
     WHERE id = $1`,
    [userId, fullName ?? null, email ?? null, roleId ?? null],
  );
}

// ---- Listing ---------------------------------------------------------------------------------------

export async function listUsers() {
  const { rows } = await pool.query(
    `SELECT ${PUBLIC},
       COALESCE((SELECT json_agg(r2.name ORDER BY r2.name) FROM user_roles ur JOIN roles r2 ON r2.id = ur.role_id WHERE ur.user_id = u.id), '[]') AS additional_roles,
       (SELECT COUNT(*)::int FROM user_sessions s WHERE s.user_id = u.id AND s.revoked_at IS NULL AND s.expires_at > now()) AS active_sessions
     FROM users u JOIN roles r ON r.id = u.role_id ORDER BY u.username`,
  );
  return rows;
}

export async function findRoleId(name) {
  const { rows } = await pool.query('SELECT id FROM roles WHERE name=$1', [name]);
  return rows[0]?.id;
}

export async function listRoles() {
  const { rows } = await pool.query(
    `SELECT r.id, r.name, COALESCE(json_agg(p.key ORDER BY p.key) FILTER (WHERE p.key IS NOT NULL), '[]') AS permissions,
       (SELECT COUNT(*)::int FROM users u WHERE u.role_id = r.id) AS users
     FROM roles r LEFT JOIN role_permissions rp ON rp.role_id = r.id LEFT JOIN permissions p ON p.id = rp.permission_id
     GROUP BY r.id ORDER BY r.id`,
  );
  return rows;
}

export async function listPermissions() {
  const { rows } = await pool.query('SELECT key,description FROM permissions ORDER BY key');
  return rows;
}

export async function listRolePermissionKeys(roleId) {
  const { rows } = await pool.query(
    'SELECT p.key FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=$1 ORDER BY p.key',
    [roleId],
  );
  return rows.map((row) => row.key);
}
