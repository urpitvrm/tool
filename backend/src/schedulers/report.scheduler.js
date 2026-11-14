import os from 'node:os';
import { randomUUID } from 'node:crypto';
import { config } from '../config/index.js';
import { pool } from '../config/db.js';
import * as scheduleModel from '../models/schedule.model.js';
import { expireHistory } from '../models/report.model.js';
import { processExecution } from '../jobs/report-execution.job.js';
import { ensureStorage, removeReportFile } from '../services/storage.service.js';
import { computeNextRun } from '../utils/schedule-time.js';

// Database-backed scheduler. All state lives in PostgreSQL (report_schedules.next_run_at and the
// report_execution_history queue), so it survives restarts, and row locks with SKIP LOCKED plus
// UNIQUE(schedule_id, scheduled_for) guarantee one execution per occurrence across instances.

const workerId = `${os.hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
const JOBS_PER_TICK = 5;
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;

let timer = null;
let ticking = false;
let stopping = false;
let currentJob = null;
let lastCleanup = 0;

/** Turn due schedule occurrences into queued executions and advance next_run_at. */
export async function enqueueDueSchedules(now = new Date()) {
  const client = await pool.connect();
  let enqueued = 0;
  try {
    await client.query('BEGIN');
    const due = await scheduleModel.lockDueSchedules(client);
    for (const schedule of due) {
      const id = await scheduleModel.enqueueExecution(client, {
        scheduleId: schedule.id, scheduleName: schedule.name, scheduledFor: schedule.next_run_at, maxAttempts: config.scheduler.maxAttempts,
      });
      if (id) enqueued += 1;
      // Occurrences missed while the service was down collapse into this single catch-up run.
      let nextRunAt = null;
      try {
        nextRunAt = computeNextRun(schedule, new Date(Math.max(now.getTime(), new Date(schedule.next_run_at).getTime())));
      } catch (error) {
        console.error(`Schedule ${schedule.id} has an invalid cadence and was completed: ${error.message}`);
      }
      await scheduleModel.advanceSchedule(client, schedule.id, nextRunAt);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  return enqueued;
}

async function processQueue() {
  for (let index = 0; index < JOBS_PER_TICK && !stopping; index += 1) {
    const execution = await scheduleModel.claimExecution(workerId, config.scheduler.staleJobMinutes);
    if (!execution) return;
    currentJob = processExecution(execution);
    await currentJob;
    currentJob = null;
  }
}

async function cleanupExpiredReports() {
  if (Date.now() - lastCleanup < CLEANUP_INTERVAL_MS) return;
  lastCleanup = Date.now();
  const expired = await expireHistory(config.reports.retentionDays);
  for (const row of expired) await removeReportFile(row.old_path).catch(() => {});
  if (expired.length) console.log(`Report retention: removed ${expired.length} expired report file(s).`);
}

async function tick() {
  if (ticking || stopping) return;
  ticking = true;
  try {
    await enqueueDueSchedules();
    await processQueue();
    await cleanupExpiredReports();
  } catch (error) {
    console.error('Report scheduler tick failed:', error.message);
  } finally {
    ticking = false;
    if (!stopping) timer = setTimeout(tick, config.scheduler.pollIntervalMs);
  }
}

export function startReportScheduler() {
  if (timer || ticking) return;
  if (!config.scheduler.enabled) {
    console.log('Report scheduler disabled (SCHEDULER_ENABLED=false); this instance will not run scheduled reports.');
    return;
  }
  stopping = false;
  ensureStorage()
    .then(() => {
      console.log(`Report scheduler started (worker ${workerId}, poll ${config.scheduler.pollIntervalMs} ms).`);
      tick();
    })
    .catch((error) => console.error('Report storage is not writable; scheduler not started:', error.message));
}

export async function stopReportScheduler() {
  stopping = true;
  if (timer) clearTimeout(timer);
  timer = null;
  // Let an in-flight job finish so it is not left in the `running` state.
  if (currentJob) await currentJob.catch(() => {});
}
