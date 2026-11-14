import test from 'node:test';
import assert from 'node:assert/strict';
import { computeNextRun, resolvePeriod, scheduleCronExpression, validateCronExpression } from '../src/utils/schedule-time.js';
import { histogramInterval, parseTimeRange } from '../src/utils/time-range.js';

const now = new Date('2026-11-12T16:00:00Z'); // 21:30 in Asia/Kolkata

test('daily schedules run at the local time of their time zone', () => {
  const next = computeNextRun({ frequency: 'daily', start_date: '2026-11-01', start_time: '09:00', timezone: 'Asia/Kolkata' }, now);
  assert.equal(next.toISOString(), '2026-11-13T03:30:00.000Z');
});

test('schedules never run before their start date and time', () => {
  const next = computeNextRun({ frequency: 'daily', start_date: '2026-12-01', start_time: '06:00', timezone: 'UTC' }, now);
  assert.equal(next.toISOString(), '2026-12-01T06:00:00.000Z');
});

test('weekly schedules use the weekday of the start date', () => {
  const next = computeNextRun({ frequency: 'weekly', start_date: '2026-11-16', start_time: '08:30', timezone: 'America/New_York' }, now);
  assert.equal(next.toISOString(), '2026-11-16T13:30:00.000Z'); // Monday 08:30 EST
});

test('monthly schedules on day 29-31 fall back to the last day of shorter months', () => {
  assert.equal(scheduleCronExpression({ frequency: 'monthly', start_date: '2026-01-31', start_time: '06:00' }), '0 6 L * *');
  const next = computeNextRun({ frequency: 'monthly', start_date: '2026-01-31', start_time: '06:00', timezone: 'UTC' }, now);
  assert.equal(next.toISOString(), '2026-11-30T06:00:00.000Z');
});

test('daylight-saving transitions keep the configured local time', () => {
  const schedule = { frequency: 'daily', start_date: '2026-03-01', start_time: '09:00', timezone: 'America/New_York' };
  // US clocks spring forward on 2026-03-08: 09:00 is 14:00Z on Mar 7 (EST) and 13:00Z on Mar 8 (EDT).
  assert.equal(computeNextRun(schedule, new Date('2026-03-07T12:00:00Z')).toISOString(), '2026-03-07T14:00:00.000Z');
  assert.equal(computeNextRun(schedule, new Date('2026-03-07T20:00:00Z')).toISOString(), '2026-03-08T13:00:00.000Z');
});

test('schedules stop after their end date', () => {
  assert.equal(computeNextRun({ frequency: 'daily', start_date: '2026-11-01', start_time: '09:00', timezone: 'UTC', end_date: '2026-11-12' }, now), null);
});

test('custom cron expressions are validated and rate-limited', () => {
  assert.equal(validateCronExpression('0 */6 * * 1-5'), '0 */6 * * 1-5');
  assert.throws(() => validateCronExpression('*/5 * * * *'), /more often/);
  assert.throws(() => validateCronExpression('not a cron'), /5 fields|Invalid/);
  assert.throws(() => validateCronExpression('0 0 * * * *'), /5 fields/);
});

test('relative report periods resolve in the schedule time zone', () => {
  const week = resolvePeriod('previous_week', 'Asia/Kolkata', now);
  assert.equal(week.from.toISOString(), '2026-11-01T18:30:00.000Z'); // Monday 00:00 IST
  assert.equal(week.to.toISOString(), '2026-11-08T18:30:00.000Z');
  const day = resolvePeriod('previous_day', 'UTC', now);
  assert.equal(day.from.toISOString(), '2026-11-11T00:00:00.000Z');
  assert.equal(day.to.toISOString(), '2026-11-12T00:00:00.000Z');
});

test('time ranges accept legacy hours, minutes and explicit dates', () => {
  assert.equal(parseTimeRange({ hours: 24 }, { now }).gte, '2026-11-11T16:00:00.000Z');
  assert.equal(parseTimeRange({ minutes: 15 }, { now }).gte, '2026-11-12T15:45:00.000Z');
  const explicit = parseTimeRange({ from: '2026-11-01T00:00:00Z', to: '2026-11-02T00:00:00Z' });
  assert.equal(explicit.lte, '2026-11-02T00:00:00.000Z');
  assert.throws(() => parseTimeRange({ from: '2026-11-02T00:00:00Z', to: '2026-11-01T00:00:00Z' }), /before/);
  assert.throws(() => parseTimeRange({ from: 'yesterday' }), /Invalid/);
});

test('histogram interval scales with the range', () => {
  assert.equal(histogramInterval(parseTimeRange({ minutes: 15 }, { now })), '1m');
  assert.equal(histogramInterval(parseTimeRange({ hours: 24 }, { now })), '30m');
  assert.equal(histogramInterval(parseTimeRange({ hours: 720 }, { now })), '12h');
});
