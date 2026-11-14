import { findActiveById, permissionsForUser } from '../models/user.model.js';
import { findActiveSession } from '../models/session.model.js';
import { verifyAccessToken } from '../utils/token.js';
import { COOKIES } from '../utils/http.js';

export { requirePermission, requireAnyPermission } from './rbac.middleware.js';

// While a password change is forced, only these endpoints are usable.
const FORCED_CHANGE_ALLOWED = ['/api/v1/auth/me', '/api/v1/auth/change-password', '/api/v1/auth/logout', '/api/v1/auth/logout-all', '/api/v1/auth/sessions', '/api/v1/auth/refresh-token'];

function accessToken(req) {
  const header = req.headers.authorization;
  if (header && /^Bearer\s+/i.test(header)) return header.replace(/^Bearer\s+/i, '');
  return req.cookies?.[COOKIES.access];
}

/**
 * Verifies the access token, that its session is still active (so logout and revocation are
 * immediate), and that the account is active; attaches the user with all role permissions.
 */
export async function authenticate(req, res, next) {
  try {
    const token = accessToken(req);
    if (!token) return res.status(401).json({ error: 'Authentication required', code: 'AUTH_REQUIRED' });
    const payload = await verifyAccessToken(token);
    const [user, session] = await Promise.all([findActiveById(payload.sub), findActiveSession(payload.sid, payload.sub)]);
    if (!user || !session) return res.status(401).json({ error: 'Your session has ended. Sign in again.', code: 'SESSION_REVOKED' });
    req.user = { ...user, permissions: await permissionsForUser(user.id), session_id: session.id };
    if (user.force_password_change && !FORCED_CHANGE_ALLOWED.some((path) => req.originalUrl.split('?')[0].startsWith(path))) {
      return res.status(403).json({ error: 'You must change your password before continuing.', code: 'PASSWORD_CHANGE_REQUIRED' });
    }
    return next();
  } catch (error) {
    if (error.status === 401) return res.status(401).json({ error: error.message, code: error.code });
    return next(error);
  }
}

/** Best-effort identification (e.g. for logout with an expired access token); never rejects. */
export async function identify(req, _res, next) {
  try {
    const token = accessToken(req);
    if (token) {
      const payload = await verifyAccessToken(token);
      req.user = { id: Number(payload.sub), username: `user:${payload.sub}`, session_id: Number(payload.sid) };
    }
  } catch { /* expired or invalid: rely on the refresh cookie */ }
  next();
}
