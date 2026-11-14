import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import * as sessionModel from '../models/session.model.js';
import { findActiveById } from '../models/user.model.js';
import { randomToken, sha256, signAccessToken } from '../utils/token.js';

const fail = (status, code, message) => Object.assign(new Error(message), { status, code });

/** Start a session: opaque refresh token (hash stored) + short-lived access JWT bound to the session. */
export async function startSession(user, { remember = false, client }) {
  const refreshToken = randomToken();
  const lifetimeMs = remember ? config.auth.rememberDays * 86_400_000 : config.auth.sessionHours * 3_600_000;
  const expiresAt = new Date(Date.now() + lifetimeMs);
  const session = await sessionModel.createSession({
    userId: user.id, refreshHash: sha256(refreshToken), expiresAt, remember,
    ip: client.ip, userAgent: client.userAgent, device: client.device,
  });
  return { session, refreshToken, refreshExpiresAt: expiresAt, accessToken: await signAccessToken(user, session.id), remember };
}

/**
 * Rotate the refresh token. Presenting a token that was already rotated away means it was
 * copied: the whole session is revoked.
 */
export async function refreshSession(refreshToken) {
  if (!refreshToken) throw fail(401, 'REFRESH_REQUIRED', 'Sign in again.');
  const currentHash = sha256(refreshToken);
  const nextToken = randomToken();
  const session = await sessionModel.rotateRefreshToken(currentHash, sha256(nextToken));
  if (!session) {
    const reused = await sessionModel.findByPreviousToken(currentHash);
    if (reused && !reused.revoked_at) {
      await sessionModel.revokeSession(reused.id, 'refresh_token_reuse');
      await audit({ id: reused.user_id, username: `user:${reused.user_id}` }, 'auth.refresh_reuse_detected', { session_id: reused.id });
    }
    throw fail(401, 'SESSION_EXPIRED', 'Your session has ended. Sign in again.');
  }
  const user = await findActiveById(session.user_id);
  if (!user) {
    await sessionModel.revokeSession(session.id, 'account_inactive');
    throw fail(401, 'SESSION_EXPIRED', 'Your session has ended. Sign in again.');
  }
  return { user, session, refreshToken: nextToken, refreshExpiresAt: new Date(session.expires_at), accessToken: await signAccessToken(user, session.id), remember: session.remember };
}

export async function endSessionByRefreshToken(refreshToken) {
  if (!refreshToken) return null;
  const session = await sessionModel.findByRefreshToken(sha256(refreshToken));
  if (session) await sessionModel.revokeSession(session.id, 'logout');
  return session;
}

export const revokeSession = (id, reason, userId) => sessionModel.revokeSession(id, reason, userId);
export const revokeAllSessions = (userId, reason, exceptSessionId) => sessionModel.revokeAllSessions(userId, reason, exceptSessionId);

export async function listSessions(userId, currentSessionId) {
  return (await sessionModel.listSessions(userId)).map((session) => ({ ...session, current: String(session.id) === String(currentSessionId) }));
}
