import axios from 'axios';

// Sessions use HttpOnly cookies set by the API; no token is ever stored in JavaScript.
// OpenSearch can take longer than a typical CRUD request, so keep a generous timeout.
export const api = axios.create({ baseURL: import.meta.env.VITE_API_URL || '/api/v1', timeout: 30000, withCredentials: true });

// Remove tokens left in storage by earlier versions of the app.
try { localStorage.removeItem('siem_token'); } catch { /* storage unavailable */ }

const SAFE = new Set(['get', 'head', 'options']);
const readCookie = (name) => {
  const match = document.cookie.split('; ').find((part) => part.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
};

let csrfRequest = null;
async function csrfToken(force = false) {
  const existing = readCookie('siem_csrf');
  if (existing && !force) return existing;
  csrfRequest ||= axios.get(`${api.defaults.baseURL}/auth/csrf`, { withCredentials: true }).finally(() => { csrfRequest = null; });
  return (await csrfRequest).data.csrf_token;
}

api.interceptors.request.use(async (config) => {
  if (!SAFE.has(String(config.method || 'get').toLowerCase())) config.headers['X-CSRF-Token'] = await csrfToken();
  return config;
});

// Endpoints whose 401 means "wrong credentials/code", not "session expired".
const NO_REFRESH = ['/auth/login', '/auth/verify-login-otp', '/auth/verify-email', '/auth/refresh-token', '/auth/logout', '/auth/setup', '/auth/forgot-password', '/auth/verify-reset-otp', '/auth/reset-password', '/auth/accept-invitation', '/auth/resend-otp'];
let refreshRequest = null;

api.interceptors.response.use((response) => response, async (error) => {
  const { config, response } = error;
  if (!config || !response) return Promise.reject(error);
  const code = response.data?.code;

  if (response.status === 403 && code === 'CSRF_FAILED' && !config._csrfRetry) {
    config._csrfRetry = true;
    config.headers['X-CSRF-Token'] = await csrfToken(true);
    return api(config);
  }
  if (response.status === 401 && !config._authRetry && !NO_REFRESH.some((path) => String(config.url).includes(path))) {
    config._authRetry = true;
    try {
      // One refresh for all requests that failed at the same moment.
      refreshRequest ||= api.post('/auth/refresh-token').finally(() => { refreshRequest = null; });
      await refreshRequest;
      return api(config);
    } catch {
      window.dispatchEvent(new Event('siem-logout'));
    }
  }
  if (response.status === 403 && code === 'PASSWORD_CHANGE_REQUIRED') window.dispatchEvent(new Event('siem-password-change-required'));
  return Promise.reject(error);
});

export const apiError = (error) => error?.response?.data?.detail || error?.response?.data?.error || error?.message || 'Request failed';
export const apiCode = (error) => error?.response?.data?.code || '';
