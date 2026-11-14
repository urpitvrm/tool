import cronParser from 'cron-parser';
import { DateTime } from 'luxon';

const MIN_CRON_INTERVAL_MINUTES = 15;

const httpError = (message) => Object.assign(new Error(message), { status: 422 });

export function isValidTimezone(timezone) {
  return typeof timezone === 'string' && DateTime.now().setZone(timezone).isValid;
}

/** Translate a schedule's frequency into a 5-field cron expression. */
export function scheduleCronExpression({ frequency, cron_expression: cronExpression, start_date: startDate, start_time: startTime }) {
  if (frequency === 'cron') return String(cronExpression || '').trim();
  const [hour, minute] = String(startTime).split(':').map(Number);
  if (frequency === 'daily') return `${minute} ${hour} * * *`;
  const start = DateTime.fromISO(String(startDate));
  if (frequency === 'weekly') return `${minute} ${hour} * * ${start.weekday % 7}`; // luxon: Mon=1..Sun=7, cron: Sun=0
  if (frequency === 'monthly') return `${minute} ${hour} ${start.day > 28 ? 'L' : start.day} * *`; // 29–31 → last day of month
  throw httpError(`Unsupported frequency: ${frequency}`);
}

/** Validate a user-supplied cron expression (5 fields, at most every 15 minutes). */
export function validateCronExpression(expression, timezone = 'UTC') {
  const value = String(expression || '').trim();
  if (value.split(/\s+/).length !== 5) throw httpError('Cron expression must have 5 fields (minute hour day-of-month month day-of-week)');
  let interval;
  try {
    interval = cronParser.parseExpression(value, { tz: timezone });
  } catch {
    throw httpError('Invalid cron expression');
  }
  let previous = interval.next().getTime();
  for (let i = 0; i < 5; i += 1) {
    const current = interval.next().getTime();
    if (current - previous < MIN_CRON_INTERVAL_MINUTES * 60_000) {
      throw httpError(`Schedules cannot run more often than every ${MIN_CRON_INTERVAL_MINUTES} minutes`);
    }
    previous = current;
  }
  return value;
}

/** Local start of a schedule (start_date + start_time in the schedule's time zone). */
export function scheduleStart(schedule) {
  const time = String(schedule.start_time).slice(0, 5);
  return DateTime.fromISO(`${schedule.start_date}T${time}`, { zone: schedule.timezone });
}

/**
 * Next execution instant strictly after `after`, honoring start and optional end date.
 * Returns null when the schedule has no further runs.
 */
export function computeNextRun(schedule, after = new Date()) {
  const start = scheduleStart(schedule);
  if (!start.isValid) throw httpError('Invalid start date, start time or time zone');
  const lowerBound = Math.max(after.getTime(), start.toMillis() - 1000);
  const interval = cronParser.parseExpression(scheduleCronExpression(schedule), {
    currentDate: new Date(lowerBound),
    tz: schedule.timezone,
  });
  const next = interval.next().toDate();
  if (schedule.end_date) {
    const end = DateTime.fromISO(String(schedule.end_date), { zone: schedule.timezone }).endOf('day');
    if (next.getTime() > end.toMillis()) return null;
  }
  return next;
}

/** Resolve a relative reporting period at execution time, in the schedule's time zone. */
export function resolvePeriod(period, timezone = 'UTC', now = new Date()) {
  const current = DateTime.fromJSDate(now, { zone: timezone });
  const window = (from, to) => ({ from: from.toJSDate(), to: to.toJSDate() });
  switch (period) {
    case 'last_7d': return window(current.minus({ days: 7 }), current);
    case 'last_30d': return window(current.minus({ days: 30 }), current);
    case 'previous_day': { const today = current.startOf('day'); return window(today.minus({ days: 1 }), today); }
    case 'previous_week': { const week = current.startOf('week'); return window(week.minus({ weeks: 1 }), week); }
    case 'previous_month': { const month = current.startOf('month'); return window(month.minus({ months: 1 }), month); }
    case 'last_24h':
    default: return window(current.minus({ hours: 24 }), current);
  }
}

/** Default reporting period for a schedule frequency. */
export function defaultPeriodForFrequency(frequency) {
  return { daily: 'previous_day', weekly: 'previous_week', monthly: 'previous_month' }[frequency] || 'last_24h';
}
