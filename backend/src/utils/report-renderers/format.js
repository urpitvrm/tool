import { DateTime } from 'luxon';

const ISO_DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;

export function isIsoDate(value) {
  return typeof value === 'string' && ISO_DATE.test(value);
}

export function formatDate(value, timezone = 'UTC', pattern = 'yyyy-LL-dd HH:mm:ss') {
  const date = value instanceof Date ? DateTime.fromJSDate(value) : DateTime.fromISO(String(value), { setZone: true });
  return date.isValid ? date.setZone(timezone).toFormat(pattern) : String(value ?? '');
}

/** Human-readable cell text. */
export function formatCell(value, timezone) {
  if (value == null || value === '') return '';
  if (value instanceof Date || isIsoDate(value)) return formatDate(value, timezone);
  if (typeof value === 'number') return Number.isInteger(value) ? value.toLocaleString('en-US') : value.toFixed(2);
  if (typeof value === 'object') return JSON.stringify(value);
  return String(value);
}

export function describePeriod(document) {
  if (!document.period) return 'Current inventory snapshot';
  return `${formatDate(document.period.from, document.timezone, 'yyyy-LL-dd HH:mm')} – ${formatDate(document.period.to, document.timezone, 'yyyy-LL-dd HH:mm')} (${document.timezone})`;
}

const FILTER_LABELS = { severity: 'Severity', agent: 'Agent', ruleId: 'Rule ID', srcip: 'Source IP', dstip: 'Destination IP', q: 'Query', status: 'Agent status', group: 'Agent group' };

export function describeFilters(filters = {}) {
  return Object.entries(filters)
    .filter(([key, value]) => FILTER_LABELS[key] && value != null && value !== '' && !(Array.isArray(value) && !value.length))
    .map(([key, value]) => [FILTER_LABELS[key], Array.isArray(value) ? value.join(', ') : String(value)]);
}

export function safeFileName(name, extension) {
  const base = String(name || 'report').normalize('NFKD').replace(/[^\w\- ]+/g, '').trim().replace(/\s+/g, '_').slice(0, 80) || 'report';
  return `${base}_${DateTime.utc().toFormat('yyyyLLdd_HHmm')}.${extension}`;
}
