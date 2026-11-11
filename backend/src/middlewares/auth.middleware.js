import { jwtVerify } from 'jose';
import { config } from '../config/index.js';
import { findActiveById, hasPermission } from '../models/user.model.js';
import { asyncHandler } from '../utils/helpers.js';

const secret = new TextEncoder().encode(config.secret);

export async function authenticate(req, res, next) {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Authentication required' });
    const { payload } = await jwtVerify(token, secret);
    const user = await findActiveById(payload.sub);
    if (!user) return res.status(401).json({ error: 'Session invalid or user disabled' });
    req.user = user;
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

export const requirePermission = (key) => asyncHandler(async (req, res, next) => {
  if (!(await hasPermission(req.user.role_id, key))) {
    return res.status(403).json({ error: 'Permission denied', permission: key });
  }
  return next();
});
