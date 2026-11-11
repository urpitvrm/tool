import { config } from '../config/index.js';

export const asyncHandler = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

export function redactError(error) {
  const status = Number(error?.statusCode || error?.response?.status || error?.meta?.statusCode);
  if (Number.isFinite(status) && status > 0) {
    const body = error?.meta?.body || error?.response?.data || {};
    const upstreamError = body?.error;
    const type = typeof upstreamError === 'object' ? upstreamError?.type : '';
    const reason = typeof upstreamError === 'object'
      ? upstreamError?.reason || upstreamError?.root_cause?.map((item) => item.reason).filter(Boolean).join('; ')
      : typeof upstreamError === 'string' ? upstreamError : body?.message;
    const description = [type, reason].filter(Boolean).join(': ').slice(0, 140);
    return `${error?.meta ? 'OpenSearch' : 'Upstream service'} returned HTTP ${status}${description ? ` (${description})` : ''}`;
  }

  const message = String(error?.message || 'Request failed');
  if (/\b(EAI_AGAIN|ENOTFOUND)\b/i.test(message)) {
    return config.usingSupabase
      ? 'DNS lookup failed for the Supabase database host. Verify the host or use the Supabase Session Pooler connection URI.'
      : 'DNS lookup failed for a configured service host.';
  }
  return message
    .replace(/postgres(?:ql)?:\/\/[^\s@]+@[^\s/]+/ig, 'postgresql://[redacted]')
    .replace(/[a-z0-9-]+\.supabase\.co/ig, '[supabase-host]')
    .replace(/(password|token|authorization)=?[^\s&]+/ig, '$1=[redacted]')
    .slice(0, 180);
}

export function errorHandler(error, _req, res, _next) {
  if (res.headersSent) return;
  if (error.status) return res.status(error.status).json({ error: error.message });
  console.error('API request failed:', redactError(error));
  return res.status(503).json({ error: 'Integration or service unavailable', detail: redactError(error) });
}
