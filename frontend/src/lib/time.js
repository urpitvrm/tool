// Shared time-range model: { preset: '24h' } or { preset: 'custom', from, to } (datetime-local strings).
export const RANGE_PRESETS = [
  { key: '15m', label: 'Last 15 minutes', minutes: 15 },
  { key: '1h', label: 'Last hour', minutes: 60 },
  { key: '4h', label: 'Last 4 hours', minutes: 240 },
  { key: '12h', label: 'Last 12 hours', minutes: 720 },
  { key: '24h', label: 'Last 24 hours', minutes: 1440 },
  { key: '7d', label: 'Last 7 days', minutes: 10080 },
  { key: '30d', label: 'Last 30 days', minutes: 43200 },
  { key: 'custom', label: 'Custom range' },
];

const presetOf = (key) => RANGE_PRESETS.find((preset) => preset.key === key) || RANGE_PRESETS[4];

export function isCustomComplete(range) {
  return range?.preset === 'custom' && range.from && range.to && new Date(range.from) < new Date(range.to);
}

/** Query parameters understood by the backend (`minutes`, or `from`/`to`). */
export function rangeParams(range) {
  if (isCustomComplete(range)) return { from: new Date(range.from).toISOString(), to: new Date(range.to).toISOString() };
  return { minutes: presetOf(range?.preset).minutes || 1440 };
}

/** Whole hours, for older module endpoints that only accept `hours`. */
export function rangeHours(range) {
  if (isCustomComplete(range)) return Math.max(1, Math.ceil((new Date(range.to) - new Date(range.from)) / 3_600_000));
  return Math.max(1, Math.ceil((presetOf(range?.preset).minutes || 1440) / 60));
}

export function rangeLabel(range) {
  if (isCustomComplete(range)) return `${new Date(range.from).toLocaleString()} – ${new Date(range.to).toLocaleString()}`;
  return presetOf(range?.preset).label;
}

/** `datetime-local` input value for a Date. */
export function toLocalInput(date) {
  const value = new Date(date);
  const offset = value.getTimezoneOffset() * 60_000;
  return new Date(value.getTime() - offset).toISOString().slice(0, 16);
}

export const browserTimezone = () => Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';

export function timezoneOptions() {
  try {
    const zones = Intl.supportedValuesOf('timeZone');
    return zones.includes('UTC') ? zones : ['UTC', ...zones];
  } catch {
    return ['UTC', browserTimezone()];
  }
}
