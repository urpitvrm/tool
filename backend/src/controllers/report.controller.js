import * as reportService from '../services/report.service.js';
import * as scheduleService from '../services/schedule.service.js';
import { smtpConfigured } from '../services/email.service.js';
import { config } from '../config/index.js';
import { validate } from '../validators/validate.js';
import { generateReportSchema, historyQuerySchema, scheduleSchema, templateSchema } from '../validators/report.validator.js';

const id = (value) => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw Object.assign(new Error('Invalid identifier'), { status: 422 });
  return parsed;
};

function sendFile(res, { stream, fileName, mime, size }) {
  res.setHeader('Content-Type', mime);
  res.setHeader('Content-Disposition', `attachment; filename="${fileName.replace(/["\\\r\n]/g, '_')}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  if (size) res.setHeader('Content-Length', String(size));
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

// ---- Catalog / generation ---------------------------------------------------

export async function catalog(req, res) {
  res.json({
    types: reportService.getCatalog(),
    formats: ['pdf', 'xlsx', 'csv'],
    periods: ['last_24h', 'last_7d', 'last_30d', 'previous_day', 'previous_week', 'previous_month'],
    capabilities: {
      manage: await reportService.canManageReports(req.user),
      smtp_configured: smtpConfigured(),
      max_rows: config.reports.maxRows,
      pdf_max_rows: config.reports.pdfMaxRows,
      allowed_email_domains: config.reports.allowedEmailDomains,
    },
  });
}

export async function generate(req, res) {
  const body = validate(generateReportSchema, req.body);
  const range = reportService.resolveReportRange({ reportType: body.report_type, start: body.start, end: body.end, period: body.period, timezone: body.timezone });
  const record = await reportService.generateReport({
    name: body.name, reportType: body.report_type, format: body.format, range, filters: body.filters, columns: body.columns,
    user: req.user, templateId: body.template_id, timezone: body.timezone,
  });
  res.status(201).json(record);
}

// ---- History ----------------------------------------------------------------

export async function history(req, res) {
  res.json(await reportService.listHistory(req.user, validate(historyQuerySchema, req.query)));
}

export async function historyItem(req, res) {
  res.json(await reportService.getHistory(req.user, id(req.params.id)));
}

export async function download(req, res) {
  sendFile(res, await reportService.downloadForUser(req.user, id(req.params.id)));
}

export async function downloadWithToken(req, res) {
  sendFile(res, await reportService.downloadWithToken(String(req.params.token)));
}

export async function deleteHistory(req, res) {
  await reportService.deleteReport(req.user, id(req.params.id));
  res.status(204).end();
}

// ---- Templates --------------------------------------------------------------

export async function templates(req, res) {
  res.json(await reportService.listTemplates(req.user));
}

export async function createTemplate(req, res) {
  res.status(201).json(await reportService.createTemplate(req.user, validate(templateSchema, req.body)));
}

export async function updateTemplate(req, res) {
  res.json(await reportService.updateTemplate(req.user, id(req.params.id), validate(templateSchema, req.body)));
}

export async function deleteTemplate(req, res) {
  await reportService.deleteTemplate(req.user, id(req.params.id));
  res.status(204).end();
}

// ---- Schedules --------------------------------------------------------------

export async function schedules(req, res) {
  res.json(await scheduleService.listSchedules(req.user));
}

export async function schedule(req, res) {
  res.json(await scheduleService.getSchedule(req.user, id(req.params.id)));
}

export async function createSchedule(req, res) {
  res.status(201).json(await scheduleService.createSchedule(req.user, validate(scheduleSchema, req.body)));
}

export async function updateSchedule(req, res) {
  res.json(await scheduleService.updateSchedule(req.user, id(req.params.id), validate(scheduleSchema, req.body)));
}

export async function pauseSchedule(req, res) {
  res.json(await scheduleService.pauseSchedule(req.user, id(req.params.id)));
}

export async function resumeSchedule(req, res) {
  res.json(await scheduleService.resumeSchedule(req.user, id(req.params.id)));
}

export async function deleteSchedule(req, res) {
  await scheduleService.deleteSchedule(req.user, id(req.params.id));
  res.status(204).end();
}

export async function runSchedule(req, res) {
  res.status(202).json(await scheduleService.runNow(req.user, id(req.params.id)));
}

export async function executions(req, res) {
  const page = Math.max(1, Number(req.query.page) || 1);
  const size = Math.min(100, Math.max(1, Number(req.query.size) || 25));
  res.json(await scheduleService.listExecutions(req.user, id(req.params.id), page, size));
}

export async function retryExecution(req, res) {
  res.status(202).json(await scheduleService.retryExecution(req.user, id(req.params.executionId)));
}
