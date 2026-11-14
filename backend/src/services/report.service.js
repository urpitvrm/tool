import { SignJWT, jwtVerify } from 'jose';
import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import * as reportModel from '../models/report.model.js';
import { userHasPermission } from '../models/user.model.js';
import { REPORT_TYPES, reportCatalog } from '../constants/report-types.js';
import { buildReportDocument } from './report-data.service.js';
import { FORMAT_META, renderReport } from '../utils/report-renderers/index.js';
import { describePeriod, safeFileName } from '../utils/report-renderers/format.js';
import { openReportFile, readReportFile, removeReportFile, reportFileExists, saveReportFile, STORAGE_BACKEND } from './storage.service.js';
import { resolvePeriod } from '../utils/schedule-time.js';
import { redactError } from '../utils/helpers.js';

const secret = new TextEncoder().encode(config.secret);
const DOWNLOAD_AUDIENCE = 'report-download';
const notFound = () => Object.assign(new Error('Report not found'), { status: 404 });

export const getCatalog = () => reportCatalog();

export const canManageReports = (user) => userHasPermission(user, 'reports:manage');

/** Resolve the reporting window: explicit start/end, else a named period, else the type's default. */
export function resolveReportRange({ reportType, start, end, period, timezone = 'UTC', now = new Date() }) {
  const type = REPORT_TYPES[reportType];
  const window = start && end ? { from: new Date(start), to: new Date(end) } : resolvePeriod(period || type?.defaultPeriod || 'last_24h', timezone, now);
  return { ...window, gte: window.from.toISOString(), lte: window.to.toISOString() };
}

/**
 * Generate, store and record a report. Every attempt creates a report_history row.
 * Returns the history record.
 */
export async function generateReport({ name, reportType, format, range, filters, columns, user, source = 'manual', scheduleId = null, templateId = null, timezone = 'UTC' }) {
  const historyId = await reportModel.insertHistory({
    name, report_type: reportType, format, source, start_date: range.gte, end_date: range.lte,
    filters, columns, generated_by: user?.id, schedule_id: scheduleId, configuration_id: templateId,
  });
  try {
    const document = await buildReportDocument({ name, reportType, range, filters, columns, generatedBy: user?.username, timezone });
    const buffer = await renderReport(document, format);
    const { extension } = FORMAT_META[format];
    const { key, size } = await saveReportFile(buffer, extension);
    const rowCount = document.details?.rows.length ?? document.sections.find((section) => section.primary)?.rows.length ?? null;
    await reportModel.completeHistory(historyId, {
      artifactPath: key, storageBackend: STORAGE_BACKEND, fileName: safeFileName(name, extension), fileSize: size, rowCount,
    });
    await audit(user, 'report.generate', { id: historyId, report_type: reportType, format, source });
    return reportModel.findHistory(historyId);
  } catch (error) {
    await reportModel.failHistory(historyId, error.status ? error.message : redactError(error)).catch(() => {});
    throw error;
  }
}

async function accessibleHistory(user, id) {
  const record = await reportModel.findHistory(id);
  if (!record) throw notFound();
  if (record.generated_by !== user.id && !(await canManageReports(user))) throw notFound();
  return record;
}

export async function listHistory(user, query) {
  const manage = await canManageReports(user);
  return reportModel.listHistory({
    ownerId: manage ? null : user.id,
    q: query.q, reportType: query.report_type, status: query.status, format: query.format,
    userId: manage ? query.user_id : undefined, page: query.page, size: query.size,
  });
}

export async function getHistory(user, id) {
  const { artifact_path: _path, ...record } = await accessibleHistory(user, id);
  return record;
}

/** Returns { stream, fileName, mime, size } for an authorized download. */
export async function openDownload(record) {
  if (record.status !== 'completed' || !record.artifact_path || !(await reportFileExists(record.artifact_path))) {
    throw Object.assign(new Error('The report file is no longer available'), { status: 410 });
  }
  return {
    stream: openReportFile(record.artifact_path),
    fileName: record.file_name || `report-${record.id}.${FORMAT_META[record.format]?.extension || 'bin'}`,
    mime: FORMAT_META[record.format]?.mime || 'application/octet-stream',
    size: record.file_size,
  };
}

export async function downloadForUser(user, id) {
  const record = await accessibleHistory(user, id);
  await audit(user, 'report.download', { id });
  return openDownload(record);
}

export async function deleteReport(user, id) {
  const record = await accessibleHistory(user, id);
  await reportModel.deleteHistory(id);
  await removeReportFile(record.artifact_path).catch(() => {});
  await audit(user, 'report.delete', { id, name: record.name });
}

// ---- Signed, expiring download links (used in emails) --------------------

export async function createDownloadLink(historyId) {
  const expiresAt = new Date(Date.now() + config.reports.linkTtlHours * 3_600_000);
  const token = await new SignJWT({ rid: String(historyId) })
    .setProtectedHeader({ alg: 'HS256' })
    .setAudience(DOWNLOAD_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(secret);
  return { url: `${config.publicBaseUrl}/api/v1/reports/download/${token}`, expiresAt };
}

export async function downloadWithToken(token) {
  let payload;
  try {
    ({ payload } = await jwtVerify(token, secret, { audience: DOWNLOAD_AUDIENCE }));
  } catch {
    throw Object.assign(new Error('This download link is invalid or has expired'), { status: 403 });
  }
  const record = await reportModel.findHistory(payload.rid);
  if (!record) throw notFound();
  await audit({ username: 'signed-link' }, 'report.download_link', { id: record.id });
  return openDownload(record);
}

export async function readReportBuffer(record) {
  return readReportFile(record.artifact_path);
}

export function emailReportSummary(record, timezone) {
  return {
    name: record.name,
    typeLabel: REPORT_TYPES[record.report_type]?.label || record.report_type,
    period: REPORT_TYPES[record.report_type]?.periodless ? 'Current inventory snapshot'
      : describePeriod({ period: { from: record.start_date, to: record.end_date }, timezone }),
    format: record.format,
  };
}

// ---- Templates ---------------------------------------------------------------

async function accessibleTemplate(user, id) {
  const template = await reportModel.findTemplate(id);
  if (!template || (template.created_by !== user.id && !(await canManageReports(user)))) {
    throw Object.assign(new Error('Template not found'), { status: 404 });
  }
  return template;
}

export async function listTemplates(user) {
  return reportModel.listTemplates((await canManageReports(user)) ? null : user.id);
}

export const getTemplate = accessibleTemplate;

export async function createTemplate(user, body) {
  const template = await reportModel.insertTemplate(body, user.id);
  await audit(user, 'report.template_create', { id: template.id });
  return template;
}

export async function updateTemplate(user, id, body) {
  await accessibleTemplate(user, id);
  const template = await reportModel.updateTemplate(id, body);
  await audit(user, 'report.template_update', { id });
  return template;
}

export async function deleteTemplate(user, id) {
  await accessibleTemplate(user, id);
  await reportModel.deleteTemplate(id);
  await audit(user, 'report.template_delete', { id });
}
