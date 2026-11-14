import * as authService from '../services/auth.service.js';
import * as sessionService from '../services/session.service.js';
import { listLoginHistory } from '../models/session.model.js';
import { audit } from '../config/db.js';
import { validate } from '../validators/validate.js';
import { loginSchema, setupSchema } from '../validators/auth.validator.js';
import { verifyOtpSchema } from '../validators/otp.validator.js';
import { clearSessionCookies, clientInfo, COOKIES, ensureCsrfCookie, setSessionCookies } from '../utils/http.js';

/** Sets session cookies; the response body never contains tokens. */
export function sendAuthenticated(res, result) {
  if (result.status !== 'authenticated') return res.json(result);
  setSessionCookies(res, result.tokens);
  return res.json({ status: 'authenticated', user: result.user });
}

export function csrf(req, res) {
  res.json({ csrf_token: ensureCsrfCookie(req, res) });
}

export async function login(req, res) {
  const body = validate(loginSchema, req.body);
  sendAuthenticated(res, await authService.login(body, clientInfo(req)));
}

export async function verifyLoginOtp(req, res) {
  const body = validate(verifyOtpSchema, req.body);
  sendAuthenticated(res, await authService.verifyLoginOtp({ challengeId: body.challenge_id, otp: body.otp }, clientInfo(req)));
}

export async function refreshToken(req, res) {
  try {
    const result = await sessionService.refreshSession(req.cookies?.[COOKIES.refresh]);
    setSessionCookies(res, result);
    res.json({ status: 'refreshed', expires_at: result.refreshExpiresAt });
  } catch (error) {
    clearSessionCookies(res);
    throw error;
  }
}

export async function logout(req, res) {
  const session = await sessionService.endSessionByRefreshToken(req.cookies?.[COOKIES.refresh]);
  if (req.user?.session_id) await sessionService.revokeSession(req.user.session_id, 'logout', req.user.id);
  if (session || req.user) await audit(req.user || { id: session.user_id, username: `user:${session.user_id}` }, 'auth.logout', {});
  clearSessionCookies(res);
  res.json({ status: 'signed_out' });
}

export async function logoutAll(req, res) {
  const revoked = await sessionService.revokeAllSessions(req.user.id, 'logout_all');
  await audit(req.user, 'auth.logout_all', { sessions_revoked: revoked });
  clearSessionCookies(res);
  res.json({ status: 'signed_out', sessions_revoked: revoked });
}

export async function me(req, res) {
  res.json(await authService.profile(req.user.id, req.user.session_id));
}

export async function sessions(req, res) {
  res.json(await sessionService.listSessions(req.user.id, req.user.session_id));
}

export async function deleteSession(req, res) {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(422).json({ error: 'Invalid session', code: 'VALIDATION' });
  if (!(await sessionService.revokeSession(id, 'revoked_by_user', req.user.id))) return res.status(404).json({ error: 'Session not found', code: 'NOT_FOUND' });
  await audit(req.user, 'auth.session_revoked', { session_id: id });
  if (id === req.user.session_id) clearSessionCookies(res);
  res.status(204).end();
}

export async function loginHistory(req, res) {
  res.json(await listLoginHistory(req.user.id, Math.min(200, Math.max(1, Number(req.query.limit) || 50))));
}

export async function setupStatus(_req, res) {
  res.json(await authService.setupStatus());
}

export async function setup(req, res) {
  const body = validate(setupSchema, req.body);
  res.status(201).json(await authService.setupSuperAdmin({
    setupToken: body.setup_token, fullName: body.full_name, username: body.username, email: body.email, password: body.password,
  }, clientInfo(req)));
}
