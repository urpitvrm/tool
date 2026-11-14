import { pool } from '../config/db.js';

export async function findActiveById(id) {
  const { rows } = await pool.query(
    'SELECT u.id,u.username,u.role_id,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=$1 AND u.disabled=false',
    [id],
  );
  return rows[0] || null;
}

export async function findByUsername(username) {
  const { rows } = await pool.query(
    'SELECT u.*,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE username=$1',
    [username],
  );
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

export async function insertUser(username, passwordHash, roleId) {
  const { rows } = await pool.query(
    'INSERT INTO users(username,password_hash,role_id) VALUES($1,$2,$3) RETURNING id,username,role_id',
    [username, passwordHash, roleId],
  );
  return rows[0];
}

export async function createSession(userId, tokenHash) {
  await pool.query("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '8 hours')", [userId, tokenHash]);
}

export async function hasPermission(roleId, permissionKey) {
  const { rows } = await pool.query(
    'SELECT 1 FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=$1 AND p.key=$2',
    [roleId, permissionKey],
  );
  return rows.length > 0;
}

export async function listUsers() {
  const { rows } = await pool.query('SELECT u.id,u.username,u.disabled,u.created_at,r.name role FROM users u JOIN roles r ON r.id=u.role_id ORDER BY username');
  return rows;
}

export async function findRoleId(name) {
  const { rows } = await pool.query('SELECT id FROM roles WHERE name=$1', [name]);
  return rows[0]?.id;
}

export async function listRoles() {
  const { rows } = await pool.query('SELECT id,name FROM roles ORDER BY id');
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
