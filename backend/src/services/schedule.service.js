import { config } from '../config/index.js';
import { audit, pool } from '../config/db.js';
import * as scheduleModel from '../models/schedule.model.js';
import { canManageReports } from './report.service.js';
import { assertAllowedRecipients } from './email.service.js';
import { computeNextRun, validateCronExpression } from '../utils/schedule-time.js';

const notFound = () => Object.assign(new Error('Schedule not found'), { status: 404 });
const forbidden = (message) => Object.assign(new Error(message), { status: 403 });

async function accessibleSchedule(user, id) {
  const schedule = await scheduleModel.findSchedule(id);
  if (!schedule || (schedule.created_by !== user.id && !(await canManageReports(user)))) throw notFound();
  return schedule;
}

/** Permission-dependent checks shared by create and update. */
async function authorize(user, body) {
  const manage = await canManageReports(user);
  if (body.frequency === 'cron') {
    if (!manage) throw forbidden('Custom cron schedules require the reports:manage permission');
    body.cron_expression = validateCronExpression(body.cron_expression, body.timezone);
  } else {
    body.cron_expression = null;
  }
  if ((body.cc?.length || body.bcc?.length) && !manage) throw forbidden('CC and BCC recipients require the reports:manage permission');
  assertAllowedRecipients([...body.recipients, ...(body.cc || []), ...(body.bcc || [])]);
}

function withNextRun(body) {
  const nextRunAt = body.status === 'active' ? computeNextRun(body) : null;
  if (body.status === 'active' && !nextRunAt) throw Object.assign(new Error('The schedule has no future run before its end date'), { status: 422 });
  return { ...body, next_run_at: nextRunAt };
}

export async function listSchedules(user) {
  return scheduleModel.listSchedules((await canManageReports(user)) ? null : user.id);
}

export const getSchedule = accessibleSchedule;

export async function createSchedule(user, body) {
  await authorize(user, body);
  const schedule = await scheduleModel.insertSchedule(withNextRun(body), user.id);
  await audit(user, 'schedule.create', { id: schedule.id, name: schedule.name, recipients: body.recipients.length });
  return schedule;
}

export async function updateSchedule(user, id, body) {
  const existing = await accessibleSchedule(user, id);
  await authorize(user, body);
  // A schedule that ran to completion becomes active again only if it is re-enabled.
  const status = existing.status === 'completed' && body.status === 'paused' ? 'paused' : body.status;
  const schedule = await scheduleModel.updateSchedule(id, withNextRun({ ...body, status }));
  await audit(user, 'schedule.update', { id });
  return schedule;
}

export async function pauseSchedule(user, id) {
  await accessibleSchedule(user, id);
  const schedule = await scheduleModel.updateSchedule(id, { status: 'paused', next_run_at: null });
  await audit(user, 'schedule.pause', { id });
  return schedule;
}

export async function resumeSchedule(user, id) {
  const existing = await accessibleSchedule(user, id);
  const nextRunAt = computeNextRun(existing);
  if (!nextRunAt) throw Object.assign(new Error('The schedule has passed its end date. Edit the end date to resume it.'), { status: 422 });
  const schedule = await scheduleModel.updateSchedule(id, { status: 'active', next_run_at: nextRunAt });
  await audit(user, 'schedule.resume', { id });
  return schedule;
}

export async function deleteSchedule(user, id) {
  await accessibleSchedule(user, id);
  await scheduleModel.deleteSchedule(id);
  await audit(user, 'schedule.delete', { id });
}

/** Queue an immediate execution, independent of the regular cadence. */
export async function runNow(user, id) {
  const schedule = await accessibleSchedule(user, id);
  const executionId = await scheduleModel.enqueueExecution(pool, {
    scheduleId: schedule.id, scheduleName: schedule.name, scheduledFor: new Date(), trigger: 'manual', maxAttempts: config.scheduler.maxAttempts,
  });
  await audit(user, 'schedule.run_now', { id, execution_id: executionId });
  return { queued: Boolean(executionId), execution_id: executionId };
}

export async function listExecutions(user, id, page, size) {
  await accessibleSchedule(user, id);
  return scheduleModel.listExecutions(id, page, size);
}

export async function retryExecution(user, executionId) {
  const execution = await scheduleModel.findExecution(executionId);
  if (!execution || !execution.schedule_id) throw Object.assign(new Error('Execution not found'), { status: 404 });
  await accessibleSchedule(user, execution.schedule_id);
  const requeued = await scheduleModel.requeueExecution(executionId);
  if (!requeued) throw Object.assign(new Error('Only failed executions can be retried'), { status: 409 });
  await audit(user, 'schedule.retry', { id: execution.schedule_id, execution_id: executionId, stage: requeued.stage });
  return requeued;
}
