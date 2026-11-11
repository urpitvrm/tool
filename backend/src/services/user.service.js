import argon2 from 'argon2';
import { SignJWT } from 'jose';
import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import * as users from '../models/user.model.js';

const secret = new TextEncoder().encode(config.secret);

export async function bootstrapUser(username, password) {
  if (await users.countUsers()) throw Object.assign(new Error('Initial administrator already exists'), { status: 403 });
  const roleId = await users.getBootstrapRoleId();
  if (!roleId) throw new Error('Bootstrap administrator role is not configured');
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const created = await users.insertUser(username, passwordHash, roleId);
  const user = { ...created, role: 'Super Administrator' };
  await audit(user, 'auth.bootstrap');
  return user;
}

export async function login(username, password) {
  const user = await users.findByUsername(username);
  if (!user || user.disabled || !(await argon2.verify(user.password_hash, password))) {
    await audit({ username }, 'auth.login_failed');
    throw Object.assign(new Error('Invalid username or password'), { status: 401 });
  }
  const token = await new SignJWT({ role: user.role })
    .setProtectedHeader({ alg: 'HS256' }).setSubject(String(user.id)).setIssuedAt().setExpirationTime('8h').sign(secret);
  await users.createSession(user.id, await argon2.hash(token));
  await audit(user, 'auth.login');
  return { access_token: token, token_type: 'bearer', username };
}

export async function createUser(username, password, role) {
  const roleId = await users.findRoleId(role);
  if (!roleId) throw Object.assign(new Error('Unknown role'), { status: 422 });
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  return users.insertUser(username, passwordHash, roleId);
}
