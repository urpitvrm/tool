import { api, apiError } from '../api.js';

export const fmtNumber = (value) => (value == null || Number.isNaN(Number(value)) ? '—' : Number(value).toLocaleString());

export function fmtDate(value, options) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString([], options);
}

export function fmtBytes(bytes) {
  const value = Number(bytes);
  if (!value) return '—';
  const units = ['B', 'KB', 'MB', 'GB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`;
}

// Wazuh rule.level bands; must match backend/src/constants/severity.js.
// Status-style steps validated for CVD separation (worst adjacent ΔE 11.3). Severity colors are
// never the only cue: charts always carry a legend/labels and stack in this fixed order.
export const SEVERITIES = [
  { key: 'critical', label: 'Critical', levels: '15+', color: '#d03b3b' },
  { key: 'high', label: 'High', levels: '12–14', color: '#ec835a' },
  { key: 'medium', label: 'Medium', levels: '7–11', color: '#fab219' },
  { key: 'low', label: 'Low', levels: '0–6', color: '#4b8ee0' },
];

// Fixed categorical order for non-severity series (entities keep their slot; never cycled).
export const SERIES_COLORS = ['#4b8ee0', '#25a37e', '#9474ef', '#d65a8c', '#2a9fb3'];

export function severityOf(level) {
  const value = Number(level);
  if (!Number.isFinite(value)) return 'unknown';
  if (value >= 15) return 'critical';
  if (value >= 12) return 'high';
  if (value >= 7) return 'medium';
  return 'low';
}

export const titleCase = (value) => String(value || '').replaceAll('_', ' ').replace(/\b\w/g, (char) => char.toUpperCase());

/** Blob error bodies hide the JSON message; unwrap it for display. */
export async function blobError(error) {
  const data = error?.response?.data;
  if (data instanceof Blob) {
    try {
      const parsed = JSON.parse(await data.text());
      return parsed.detail || parsed.error || apiError(error);
    } catch { /* fall through */ }
  }
  return apiError(error);
}

function fileNameFrom(headers, fallback) {
  const match = /filename="?([^";]+)"?/i.exec(headers?.['content-disposition'] || '');
  return match?.[1] || fallback;
}

/** Download an authenticated API resource as a file. */
export async function downloadFile(url, fallbackName, params) {
  try {
    const response = await api.get(url, { params, responseType: 'blob', timeout: 300_000 });
    const href = URL.createObjectURL(response.data);
    const anchor = document.createElement('a');
    anchor.href = href;
    anchor.download = fileNameFrom(response.headers, fallbackName);
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(href), 1000);
  } catch (error) {
    throw new Error(await blobError(error));
  }
}

export const splitList = (text) => String(text || '').split(/[,\s;]+/).map((item) => item.trim()).filter(Boolean);
