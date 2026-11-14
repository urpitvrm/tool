import rateLimit from 'express-rate-limit';

// AUTH_RATE_LIMIT_MULTIPLIER scales every limit (keep 1 in production; raise only for automated tests).
const multiplier = Math.max(1, Number(process.env.AUTH_RATE_LIMIT_MULTIPLIER) || 1);
const limiter = (windowMs, limit, message, keyGenerator) => rateLimit({
  windowMs, limit: limit * multiplier, standardHeaders: true, legacyHeaders: false,
  message: { error: message, code: 'RATE_LIMITED' },
  ...(keyGenerator ? { keyGenerator } : {}),
});

const ip = (req) => `ip:${req.ip || ''}`;
const bodyKey = (field) => (req) => `${field}:${String(req.body?.[field] || '').trim().toLowerCase().slice(0, 200) || ip(req)}`;

// Per client IP.
export const loginIpLimit = limiter(60_000, 10, 'Too many sign-in attempts from this address. Wait a minute and try again.');
export const otpIpLimit = limiter(60_000, 20, 'Too many verification attempts. Wait a minute and try again.');
export const resendIpLimit = limiter(60_000, 6, 'Too many code requests. Wait a minute and try again.');
export const recoveryIpLimit = limiter(15 * 60_000, 10, 'Too many password reset requests. Try again later.');
export const sensitiveIpLimit = limiter(15 * 60_000, 20, 'Too many requests. Try again later.');
export const refreshIpLimit = limiter(60_000, 60, 'Too many session refresh requests.');

// Per account / challenge, regardless of source IP (slows distributed guessing).
export const loginAccountLimit = limiter(15 * 60_000, 20, 'Too many sign-in attempts for this account. Try again later.', bodyKey('identifier'));
export const otpChallengeLimit = limiter(15 * 60_000, 10, 'Too many attempts for this code. Request a new one.', bodyKey('challenge_id'));
export const recoveryAccountLimit = limiter(15 * 60_000, 3, 'Too many password reset requests for this address. Try again later.', bodyKey('email'));
