import { z } from 'zod';
import { REPORT_FORMATS, REPORT_PERIODS, REPORT_TYPE_KEYS } from '../constants/report-types.js';
import { SEVERITY_NAMES } from '../constants/severity.js';
import { isValidTimezone } from '../utils/schedule-time.js';

const ipOrPattern = z.string().trim().regex(/^[0-9a-fA-F:.*]{1,64}$/, 'Invalid IP address or pattern');
const plainText = (max) => z.string().trim().max(max).regex(/^[^\r\n]*$/, 'Line breaks are not allowed');
const timezone = z.string().max(64).refine(isValidTimezone, 'Unknown time zone');

export const reportFiltersSchema = z.object({
  severity: z.array(z.enum(SEVERITY_NAMES)).max(4).default([]),
  agent: z.array(plainText(120).min(1)).max(50).default([]),
  ruleId: z.array(z.string().trim().regex(/^\d{1,10}$/, 'Rule IDs are numeric')).max(50).default([]),
  srcip: z.array(ipOrPattern).max(50).default([]),
  dstip: z.array(ipOrPattern).max(50).default([]),
  q: plainText(500).default(''),
  status: z.array(z.enum(['active', 'disconnected', 'never_connected', 'pending'])).max(4).default([]),
  group: plainText(120).optional(),
}).default({});

const columns = z.array(z.string().max(80).regex(/^[\w.@-]+$/)).max(40).default([]);

const reportConfigSchema = z.object({
  filters: reportFiltersSchema,
  columns,
  period: z.enum(REPORT_PERIODS).optional(),
}).default({});

export const generateReportSchema = z.object({
  name: plainText(200).min(1),
  report_type: z.enum(REPORT_TYPE_KEYS),
  format: z.enum(REPORT_FORMATS),
  start: z.string().datetime({ offset: true }).optional(),
  end: z.string().datetime({ offset: true }).optional(),
  period: z.enum(REPORT_PERIODS).optional(),
  timezone: timezone.default('UTC'),
  filters: reportFiltersSchema,
  columns,
  template_id: z.number().int().positive().optional(),
}).refine((value) => !(value.start && value.end) || new Date(value.start) < new Date(value.end), { message: 'Start date must be before end date' });

export const templateSchema = z.object({
  name: plainText(200).min(1),
  description: z.string().max(2000).default(''),
  report_type: z.enum(REPORT_TYPE_KEYS),
  format: z.enum(REPORT_FORMATS).default('pdf'),
  options: reportConfigSchema,
});

const email = z.string().trim().toLowerCase().email().max(254);
const emailList = z.array(email).max(50);
const dateOnly = z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Use YYYY-MM-DD');

export const scheduleSchema = z.object({
  name: plainText(200).min(1),
  report_type: z.enum(REPORT_TYPE_KEYS),
  report_config: reportConfigSchema,
  format: z.enum(REPORT_FORMATS),
  frequency: z.enum(['daily', 'weekly', 'monthly', 'cron']),
  cron_expression: z.string().trim().max(120).optional().nullable(),
  start_date: dateOnly,
  start_time: z.string().regex(/^([01]\d|2[0-3]):[0-5]\d(:[0-5]\d)?$/, 'Use HH:MM (24-hour)'),
  timezone: timezone.default('UTC'),
  end_date: dateOnly.optional().nullable(),
  recipients: emailList.min(1, 'At least one recipient is required'),
  cc: emailList.default([]),
  bcc: emailList.default([]),
  email_subject: plainText(200).min(1),
  email_message: z.string().max(5000).default(''),
  delivery_method: z.enum(['attachment', 'link']).default('attachment'),
  status: z.enum(['active', 'paused']).default('active'),
}).superRefine((value, context) => {
  if (value.frequency === 'cron' && !value.cron_expression) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['cron_expression'], message: 'A cron expression is required for custom schedules' });
  }
  if (value.end_date && value.end_date < value.start_date) {
    context.addIssue({ code: z.ZodIssueCode.custom, path: ['end_date'], message: 'End date must be on or after the start date' });
  }
});

export const historyQuerySchema = z.object({
  q: z.string().max(200).optional(),
  report_type: z.enum(REPORT_TYPE_KEYS).optional(),
  status: z.enum(['running', 'completed', 'failed', 'expired']).optional(),
  format: z.enum(REPORT_FORMATS).optional(),
  user_id: z.coerce.number().int().positive().optional(),
  page: z.coerce.number().int().min(1).default(1),
  size: z.coerce.number().int().min(1).max(200).default(25),
});
