import * as users from '../models/user.model.js';
import * as userService from '../services/user.service.js';
import { audit } from '../config/db.js';
import { validate } from '../validators/validate.js';
import { credentialsSchema, createUserSchema } from '../validators/auth.validator.js';

export async function register(req, res) {
  const { username, password } = validate(credentialsSchema, req.body);
  await userService.bootstrapUser(username, password);
  res.status(201).json({ created: true });
}

export async function login(req, res) {
  const { username, password } = validate(credentialsSchema, req.body);
  res.json(await userService.login(username, password));
}

export async function me(req, res) {
  // Permissions let the UI hide actions the user cannot perform; the API still enforces them.
  res.json({ ...req.user, permissions: await users.listRolePermissionKeys(req.user.role_id) });
}

export async function listUsers(_req, res) {
  res.json(await users.listUsers());
}

export async function createUser(req, res) {
  const body = validate(createUserSchema, req.body);
  const created = await userService.createUser(body.username, body.password, body.role);
  await audit({ ...req.user, username: req.user.username }, 'user.create', { username: body.username, role: body.role });
  res.status(201).json({ id: created.id, username: created.username, disabled: false });
}

export async function listRoles(_req, res) {
  res.json(await users.listRoles());
}

export async function listPermissions(_req, res) {
  res.json(await users.listPermissions());
}
