import { COOKIES, ensureCsrfCookie, parseCookies } from '../utils/http.js';
import { safeEqual } from '../utils/token.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Parses cookies and enforces double-submit CSRF protection for state-changing requests.
 * Cookies are SameSite=Strict as well; the header check covers older browsers and subdomain attacks.
 * Pure API clients that authenticate with an Authorization header and send no cookies are exempt.
 */
export function csrfProtection(req, res, next) {
  req.cookies = parseCookies(req.headers.cookie);
  const token = ensureCsrfCookie(req, res);
  if (SAFE_METHODS.has(req.method)) return next();
  const usesCookies = Boolean(req.cookies[COOKIES.access] || req.cookies[COOKIES.refresh]);
  const bearerOnly = !usesCookies && /^Bearer\s+/i.test(req.headers.authorization || '');
  if (bearerOnly) return next();
  const header = String(req.headers['x-csrf-token'] || '');
  if (!header || !req.cookies[COOKIES.csrf] || !safeEqual(header, token)) {
    return res.status(403).json({ error: 'Security check failed. Refresh the page and try again.', code: 'CSRF_FAILED' });
  }
  return next();
}
