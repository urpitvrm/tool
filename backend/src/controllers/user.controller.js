import * as users from '../models/user.model.js';
import * as userService from '../services/user.service.js';
import { validate } from '../validators/validate.js';
import { acceptInvitationSchema, forcePasswordSchema, invitationTokenSchema, inviteUserSchema, updateUserSchema } from '../validators/auth.validator.js';
import { clientInfo } from '../utils/http.js';

const userId = (value) => {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id < 1) throw Object.assign(new Error('Invalid user id'), { status: 422 });
  return id;
};

export async function listUsers(_req, res) {
  res.json(await users.listUsers());
}

export async function getUser(req, res) {
  const user = await users.findById(userId(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ ...user, roles: await users.rolesForUser(user.id) });
}

/** Invitation-based creation; no password is set by the administrator. */
export async function createUser(req, res) {
  const body = validate(inviteUserSchema, req.body);
  res.status(201).json(await userService.inviteUser({
    fullName: body.full_name, email: body.email, username: body.username, role: body.role, additionalRoles: body.additional_roles,
  }, req.user));
}

export async function updateUser(req, res) {
  const body = validate(updateUserSchema, req.body);
  res.json(await userService.updateUser(userId(req.params.id), {
    fullName: body.full_name, email: body.email, role: body.role, additionalRoles: body.additional_roles,
  }, req.user));
}

export async function activate(req, res) { res.json(await userService.activateUser(userId(req.params.id), req.user)); }
export async function deactivate(req, res) { res.json(await userService.deactivateUser(userId(req.params.id), req.user)); }
export async function unlock(req, res) { res.json(await userService.unlockUser(userId(req.params.id), req.user)); }
export async function resendInvitation(req, res) { res.json(await userService.resendInvitation(userId(req.params.id), req.user)); }
export async function userSessions(req, res) { res.json(await userService.userSessions(userId(req.params.id))); }
export async function revokeSessions(req, res) { res.json(await userService.revokeUserSessions(userId(req.params.id), req.user)); }

export async function forcePasswordChange(req, res) {
  const body = validate(forcePasswordSchema, req.body || {});
  res.json(await userService.forcePasswordChange(userId(req.params.id), req.user, { revokeSessions: body.revoke_sessions }));
}

export async function loginHistory(req, res) {
  res.json(await userService.loginHistory(userId(req.params.id), Math.min(200, Math.max(1, Number(req.query.limit) || 50))));
}

// ---- Public invitation endpoints ---------------------------------------------------------

export async function invitationInfo(req, res) {
  const { token } = validate(invitationTokenSchema, req.body);
  res.json(await userService.invitationInfo(token));
}

export async function acceptInvitation(req, res) {
  const body = validate(acceptInvitationSchema, req.body);
  res.json(await userService.acceptInvitation({ token: body.token, password: body.password }, clientInfo(req)));
}

export async function listRoles(_req, res) {
  res.json(await users.listRoles());
}

export async function listPermissions(_req, res) {
  res.json(await users.listPermissions());
}
