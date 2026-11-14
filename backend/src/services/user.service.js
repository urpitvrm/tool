import { config } from '../config/index.js';
import { audit, pool } from '../config/db.js';
import * as users from '../models/user.model.js';
import * as otpModel from '../models/otp.model.js';
import * as sessionModel from '../models/session.model.js';
import { randomToken, sha256 } from '../utils/token.js';
import { maskEmail } from '../utils/otp.js';
import { sendInvitation, sendSecurityNotice } from './auth-email.service.js';
import { revokeAllSessions } from './session.service.js';
import { setInitialPassword } from './password.service.js';

const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

async function roleIdFor(name) {
  const id = await users.findRoleId(name);
  if (!id) throw fail(422, 'UNKNOWN_ROLE', `Unknown role: ${name}`);
  return id;
}

async function assertNotLastSuperAdmin(target, action) {
  if (target.role !== 'Super Administrator') return;
  const { rows } = await pool.query("SELECT COUNT(*)::int AS n FROM users u JOIN roles r ON r.id = u.role_id WHERE r.name = 'Super Administrator' AND u.status = 'active' AND u.id <> $1", [target.id]);
  if (rows[0].n === 0) throw fail(409, 'LAST_SUPER_ADMIN', `You cannot ${action} the last active Super Administrator.`);
}

async function getTarget(id) {
  const user = await users.findById(id);
  if (!user) throw fail(404, 'USER_NOT_FOUND', 'User not found');
  return user;
}

/** Email a single-use invitation link (only the token hash is stored). */
async function sendInvitationLink(user, inviter) {
  const token = randomToken();
  await otpModel.createChallenge({
    userId: user.id, purpose: 'INVITATION', hashFor: () => sha256(token),
    expiresMinutes: config.auth.invitationHours * 60, maxAttempts: 1, resendSeconds: 60,
  });
  const expiresAt = new Date(Date.now() + config.auth.invitationHours * 3_600_000);
  await sendInvitation(user, {
    link: `${config.publicBaseUrl}/accept-invitation?token=${encodeURIComponent(token)}`,
    expiresAt, inviterName: inviter?.full_name || inviter?.username, roleName: user.role,
  });
  return expiresAt;
}

/** Administrator creates an account in `invited` state; no password is set or emailed. */
export async function inviteUser({ fullName, email, username, role, additionalRoles = [] }, inviter) {
  if (await users.findByEmail(email)) throw fail(409, 'EMAIL_IN_USE', 'Another account already uses this email address.');
  if (await users.findByUsername(username)) throw fail(409, 'USERNAME_IN_USE', 'This username is already taken.');
  const roleId = await roleIdFor(role);
  const extraIds = await Promise.all(additionalRoles.filter((name) => name !== role).map(roleIdFor));
  const created = await users.insertUser({ username, fullName, email, roleId, status: 'invited', invitedBy: inviter.id });
  if (extraIds.length) await users.setAdditionalRoles(created.id, extraIds);
  const user = await users.findById(created.id);
  let invitationExpiresAt = null;
  let delivery = 'sent';
  try {
    invitationExpiresAt = await sendInvitationLink(user, inviter);
  } catch (error) {
    delivery = 'failed';
    console.error(`Invitation email not sent: ${error.code || error.message}`);
  }
  await audit(inviter, 'user.invite', { id: user.id, username, role, additional_roles: additionalRoles, delivery });
  return { user, invitation: { delivery, expires_at: invitationExpiresAt, destination: maskEmail(email) } };
}

export async function resendInvitation(id, admin) {
  const user = await getTarget(id);
  if (user.status !== 'invited') throw fail(409, 'NOT_INVITED', 'Only users who have not accepted their invitation can be re-invited.');
  const expiresAt = await sendInvitationLink(user, admin);
  await audit(admin, 'user.invite_resend', { id });
  return { expires_at: expiresAt, destination: maskEmail(user.email) };
}

/** Public: describe an invitation for the acceptance page without consuming it. */
export async function invitationInfo(token) {
  const invitation = await otpModel.findOpenInvitation(sha256(token));
  const user = invitation ? await users.findById(invitation.user_id) : null;
  if (!user || user.status !== 'invited') throw fail(400, 'INVITATION_INVALID', 'This invitation link is invalid, expired or already used.');
  return { username: user.username, full_name: user.full_name, email: maskEmail(user.email), role: user.role, expires_at: invitation.expires_at };
}

/** Public: the invitee proves mailbox ownership with the link and chooses a password. */
export async function acceptInvitation({ token, password }, client) {
  const invitation = await otpModel.findOpenInvitation(sha256(token));
  const user = invitation ? await users.findById(invitation.user_id) : null;
  if (!user || user.status !== 'invited') throw fail(400, 'INVITATION_INVALID', 'This invitation link is invalid, expired or already used.');
  await setInitialPassword(user, password); // validates the policy before the link is consumed
  if (!(await otpModel.consumeInvitation(sha256(token)))) throw fail(400, 'INVITATION_INVALID', 'This invitation link was already used.');
  await users.markEmailVerified(user.id);
  const status = config.auth.inviteRequiresApproval ? 'pending_approval' : 'active';
  await users.setStatus(user.id, status);
  await audit(user, 'user.invitation_accepted', { status, ip: client.ip });
  if (status === 'active') sendSecurityNotice(user, 'account_activated', {});
  return status === 'active'
    ? { status, message: 'Your account is ready. Sign in with your username or email.' }
    : { status, message: 'Your email is verified. An administrator must approve the account before you can sign in.' };
}

export async function updateUser(id, { fullName, email, role, additionalRoles }, admin) {
  const target = await getTarget(id);
  if (email && email.toLowerCase() !== String(target.email || '').toLowerCase()) {
    const other = await users.findByEmail(email);
    if (other && other.id !== target.id) throw fail(409, 'EMAIL_IN_USE', 'Another account already uses this email address.');
  }
  const roleId = role ? await roleIdFor(role) : undefined;
  if (role && role !== target.role) await assertNotLastSuperAdmin(target, 'change the role of');
  await users.updateProfile(id, { fullName, email, roleId });
  if (Array.isArray(additionalRoles)) await users.setAdditionalRoles(id, await Promise.all(additionalRoles.filter((name) => name !== (role || target.role)).map(roleIdFor)));
  // Permission changes take effect on the next request; an email change must be re-verified at next sign-in.
  await audit(admin, 'user.update', { id, fields: Object.keys({ fullName, email, role, additionalRoles }).filter((key) => ({ fullName, email, role, additionalRoles })[key] !== undefined) });
  return users.findById(id);
}

export async function activateUser(id, admin) {
  const target = await getTarget(id);
  if (target.status === 'active') return target;
  if (target.status === 'invited') throw fail(409, 'NOT_ACCEPTED', 'The user must accept the invitation and set a password first.');
  if (!target.email_verified) throw fail(409, 'EMAIL_UNVERIFIED', 'The user must verify their email address first.');
  await users.setStatus(id, 'active');
  await users.unlockUser(id);
  await audit(admin, 'user.activate', { id });
  sendSecurityNotice(target, 'account_activated', {});
  return users.findById(id);
}

export async function deactivateUser(id, admin) {
  const target = await getTarget(id);
  if (target.id === admin.id) throw fail(409, 'SELF_DEACTIVATE', 'You cannot deactivate your own account.');
  await assertNotLastSuperAdmin(target, 'deactivate');
  await users.setStatus(id, 'deactivated');
  const revoked = await revokeAllSessions(id, 'account_deactivated');
  await audit(admin, 'user.deactivate', { id, sessions_revoked: revoked });
  sendSecurityNotice(target, 'account_deactivated', {});
  return users.findById(id);
}

export async function unlockUser(id, admin) {
  await getTarget(id);
  await users.unlockUser(id);
  await audit(admin, 'user.unlock', { id });
  return users.findById(id);
}

export async function forcePasswordChange(id, admin, { revokeSessions = false } = {}) {
  await getTarget(id);
  await users.setForcePasswordChange(id, true);
  const revoked = revokeSessions ? await revokeAllSessions(id, 'forced_password_change') : 0;
  await audit(admin, 'user.force_password_change', { id, sessions_revoked: revoked });
  return users.findById(id);
}

export async function userSessions(id) {
  await getTarget(id);
  return sessionModel.listSessions(id);
}

export async function revokeUserSessions(id, admin) {
  await getTarget(id);
  const revoked = await revokeAllSessions(id, 'revoked_by_admin');
  await audit(admin, 'user.sessions_revoked', { id, count: revoked });
  return { revoked };
}

export async function loginHistory(id, limit) {
  await getTarget(id);
  return sessionModel.listLoginHistory(id, limit);
}
