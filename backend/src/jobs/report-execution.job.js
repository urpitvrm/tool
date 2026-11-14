import { config } from '../config/index.js';
import * as scheduleModel from '../models/schedule.model.js';
import * as reportModel from '../models/report.model.js';
import { findActiveById, hasPermission } from '../models/user.model.js';
import { createDownloadLink, emailReportSummary, generateReport, readReportBuffer, resolveReportRange } from '../services/report.service.js';
import { assertAllowedRecipients, isTransientEmailError, sendReportEmail } from '../services/email.service.js';
import { FORMAT_META } from '../utils/report-renderers/index.js';
import { defaultPeriodForFrequency } from '../utils/schedule-time.js';
import { formatDate } from '../utils/report-renderers/format.js';
import { redactError } from '../utils/helpers.js';

const permanent = (message) => Object.assign(new Error(message), { permanent: true });

/** Exponential backoff: 2, 4, 8 … minutes, capped at one hour. */
const backoffMs = (attempt) => Math.min(60, 2 ** attempt) * 60_000;

async function scheduleOwner(schedule) {
  const owner = schedule.created_by ? await findActiveById(schedule.created_by) : null;
  if (!owner) throw permanent('The schedule owner no longer exists or is disabled');
  // Permissions are re-checked at run time so revoked access stops future deliveries.
  if (!(await hasPermission(owner.role_id, 'reports:schedule'))) throw permanent('The schedule owner no longer has the reports:schedule permission');
  return owner;
}

async function generateStage(execution, schedule, owner) {
  const reportConfig = schedule.report_config || {};
  const range = resolveReportRange({
    reportType: schedule.report_type,
    period: reportConfig.period || defaultPeriodForFrequency(schedule.frequency),
    timezone: schedule.timezone,
    now: new Date(execution.scheduled_for),
  });
  const record = await generateReport({
    name: schedule.name, reportType: schedule.report_type, format: schedule.format, range,
    filters: reportConfig.filters || {}, columns: reportConfig.columns || [], user: owner,
    source: 'schedule', scheduleId: schedule.id, timezone: schedule.timezone,
  });
  await scheduleModel.updateExecution(execution.id, { report_history_id: record.id, stage: 'email' });
  return record;
}

async function emailStage(execution, schedule, record) {
  const recipients = schedule.recipients || [];
  const cc = schedule.cc || [];
  const bcc = schedule.bcc || [];
  // Re-validate against the current allowlist in case it changed after the schedule was saved.
  try {
    assertAllowedRecipients([...recipients, ...cc, ...bcc]);
  } catch (error) {
    throw permanent(error.message);
  }

  let deliveryMethod = schedule.delivery_method;
  let attachment;
  let link = null;
  if (deliveryMethod === 'attachment' && Number(record.file_size) <= config.reports.maxAttachmentBytes) {
    attachment = { filename: record.file_name, content: await readReportBuffer(record), contentType: FORMAT_META[record.format]?.mime };
  } else {
    deliveryMethod = 'link'; // Too large to attach (or link delivery requested).
    link = await createDownloadLink(record.id);
  }

  const attempt = execution.attempts;
  try {
    const messageId = await sendReportEmail({
      to: recipients, cc, bcc,
      subject: schedule.email_subject,
      message: schedule.email_message,
      report: emailReportSummary(record, schedule.timezone),
      attachment,
      downloadUrl: link?.url,
      linkExpiresAt: link ? `${formatDate(link.expiresAt, schedule.timezone, 'yyyy-LL-dd HH:mm')} (${schedule.timezone})` : undefined,
    });
    await scheduleModel.insertEmailDelivery({
      executionId: execution.id, scheduleId: schedule.id, reportHistoryId: record.id, recipients, cc, bcc,
      subject: schedule.email_subject, deliveryMethod, status: 'sent', attempt, messageId,
    });
  } catch (error) {
    await scheduleModel.insertEmailDelivery({
      executionId: execution.id, scheduleId: schedule.id, reportHistoryId: record.id, recipients, cc, bcc,
      subject: schedule.email_subject, deliveryMethod, status: 'failed', attempt, error: redactError(error),
    });
    error.emailStage = true;
    throw error;
  }
}

/** Run (or resume) one claimed execution. Never throws. */
export async function processExecution(execution) {
  let schedule = null;
  try {
    schedule = execution.schedule_id ? await scheduleModel.findSchedule(execution.schedule_id) : null;
    if (!schedule) throw permanent('The schedule was deleted');
    const owner = await scheduleOwner(schedule);

    let record = execution.report_history_id ? await reportModel.findHistory(execution.report_history_id) : null;
    if (execution.stage === 'generate' || !record || record.status !== 'completed' || !record.artifact_path) {
      record = await generateStage(execution, schedule, owner);
    }
    await emailStage(execution, schedule, record);

    await scheduleModel.updateExecution(execution.id, { status: 'completed', stage: 'done', error: null, completed_at: new Date(), locked_by: null, locked_at: null });
    await scheduleModel.recordScheduleRun(schedule.id, 'completed');
  } catch (error) {
    const transient = error.emailStage ? isTransientEmailError(error) : !error.permanent && !(error.status >= 400 && error.status < 500);
    const retry = transient && execution.attempts < execution.max_attempts;
    const failedStatus = error.emailStage ? 'email_failed' : 'failed';
    const message = error.permanent || error.status ? error.message : redactError(error);
    await scheduleModel.updateExecution(execution.id, {
      status: retry ? 'retrying' : failedStatus,
      error: String(message).slice(0, 1000),
      next_attempt_at: new Date(Date.now() + backoffMs(execution.attempts)),
      locked_by: null,
      locked_at: null,
      ...(retry ? {} : { completed_at: new Date() }),
    }).catch((updateError) => console.error('Failed to record execution failure:', updateError.message));
    if (schedule && !retry) await scheduleModel.recordScheduleRun(schedule.id, failedStatus).catch(() => {});
    console.error(`Report execution ${execution.id} ${retry ? 'will retry' : 'failed'}: ${message}`);
  }
}
