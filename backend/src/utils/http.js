import { randomBytes } from 'node:crypto';
import { config } from '../config/index.js';

export const COOKIES = { access: 'siem_at', refresh: 'siem_rt', csrf: 'siem_csrf' };

export function parseCookies(header = '') {
  const cookies = {};
  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    try {
      cookies[name] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      cookies[name] = part.slice(index + 1).trim();
    }
  }
  return cookies;
}

const base = () => ({ secure: config.auth.cookieSecure, sameSite: 'strict' });

/** HttpOnly access + refresh cookies. A non-"remember" session uses browser-session cookies. */
export function setSessionCookies(res, { accessToken, refreshToken, refreshExpiresAt, remember }) {
  res.cookie(COOKIES.access, accessToken, { ...base(), httpOnly: true, path: '/api', maxAge: config.auth.accessTokenMinutes * 60_000 });
  res.cookie(COOKIES.refresh, refreshToken, {
    ...base(), httpOnly: true, path: '/api/v1/auth',
    ...(remember ? { expires: refreshExpiresAt } : {}),
  });
}

export function clearSessionCookies(res) {
  res.clearCookie(COOKIES.access, { ...base(), httpOnly: true, path: '/api' });
  res.clearCookie(COOKIES.refresh, { ...base(), httpOnly: true, path: '/api/v1/auth' });
}

/** Readable CSRF cookie for the double-submit check. */
export function ensureCsrfCookie(req, res) {
  let token = req.cookies?.[COOKIES.csrf];
  if (!token || !/^[A-Za-z0-9_-]{32,}$/.test(token)) {
    token = randomBytes(24).toString('base64url');
    res.cookie(COOKIES.csrf, token, { ...base(), httpOnly: false, path: '/' });
  }
  return token;
}

export function clientInfo(req) {
  const userAgent = String(req.headers['user-agent'] || '').slice(0, 400);
  return { ip: req.ip || req.socket?.remoteAddress || '', userAgent, device: describeDevice(userAgent) };
}

/** "Chrome on Windows" from a user-agent string (no third-party parser). */
export function describeDevice(userAgent = '') {
  const ua = String(userAgent);
  const browser = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Firefox\//.test(ua) ? 'Firefox'
    : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : /curl|node|axios|python/i.test(ua) ? 'API client' : 'Unknown browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad|iOS/.test(ua) ? 'iOS'
    : /Mac OS X|Macintosh/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  return `${browser} on ${os}`;
}
