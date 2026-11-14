const MAX_RANGE_DAYS = 400;

function httpError(message) {
  return Object.assign(new Error(message), { status: 422 });
}

function toDate(value, name) {
  const date = new Date(String(value));
  if (Number.isNaN(date.getTime())) throw httpError(`Invalid ${name} date`);
  return date;
}

/**
 * Resolve a time range from request parameters.
 * Accepts `from`/`to` (ISO-8601), `minutes`, or `hours` (existing API contract).
 */
export function parseTimeRange(params = {}, { defaultHours = 24, now = new Date() } = {}) {
  let from;
  let to = params.to ? toDate(params.to, 'end') : now;

  if (params.from) {
    from = toDate(params.from, 'start');
  } else {
    const minutes = Number(params.minutes);
    const hours = Number(params.hours);
    const spanMinutes = Number.isFinite(minutes) && minutes > 0 ? minutes
      : Number.isFinite(hours) && hours > 0 ? hours * 60
        : defaultHours * 60;
    from = new Date(to.getTime() - spanMinutes * 60_000);
  }

  if (from >= to) throw httpError('Start date must be before end date');
  if (to.getTime() - from.getTime() > MAX_RANGE_DAYS * 86_400_000) throw httpError(`Time range cannot exceed ${MAX_RANGE_DAYS} days`);
  return { from, to, gte: from.toISOString(), lte: to.toISOString() };
}

/** Pick a histogram interval that yields roughly 30–120 buckets. */
export function histogramInterval({ from, to }) {
  const minutes = (to.getTime() - from.getTime()) / 60_000;
  if (minutes <= 60) return '1m';
  if (minutes <= 6 * 60) return '5m';
  if (minutes <= 24 * 60) return '30m';
  if (minutes <= 7 * 24 * 60) return '3h';
  if (minutes <= 31 * 24 * 60) return '12h';
  return '1d';
}
