import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import { config } from '../config/index.js';

const secret = new TextEncoder().encode(config.secret);
export const ACCESS_AUDIENCE = 'siem-access';

/** Short-lived access token bound to a session (`sid`), so revoking the session revokes the token. */
export async function signAccessToken(user, sessionId) {
  return new SignJWT({ sid: String(sessionId) })
    .setProtectedHeader({ alg: 'HS256' })
    .setSubject(String(user.id))
    .setAudience(ACCESS_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(`${config.auth.accessTokenMinutes}m`)
    .sign(secret);
}

/** Throws with code TOKEN_EXPIRED / TOKEN_INVALID. */
export async function verifyAccessToken(token) {
  try {
    const { payload } = await jwtVerify(token, secret, { audience: ACCESS_AUDIENCE });
    return payload;
  } catch (error) {
    throw Object.assign(new Error(error.code === 'ERR_JWT_EXPIRED' ? 'Session expired' : 'Invalid session'), {
      status: 401, code: error.code === 'ERR_JWT_EXPIRED' ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID',
    });
  }
}

/** 256-bit random token (refresh tokens, invitation links, reset grants). */
export const randomToken = () => randomBytes(32).toString('base64url');

/** Opaque tokens are stored as SHA-256 hashes; they are high-entropy so a fast hash is sufficient. */
export const sha256 = (value) => createHash('sha256').update(String(value)).digest('hex');

/** Keyed hash for low-entropy secrets (6-digit OTPs): a database leak alone cannot be brute-forced offline. */
export const keyedHash = (value) => createHmac('sha256', config.secret).update(String(value)).digest('hex');

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
