import { z } from 'zod';

export const agentOperationSchema = z.object({
  operation: z.enum(['restart', 'remove']),
  confirm: z.boolean(),
});

export const indexOperationSchema = z.object({
  operation: z.enum(['refresh', 'flush', 'open', 'close', 'delete']),
  confirm: z.boolean(),
});

export const incidentCreateSchema = z.object({
  title: z.string().min(1).max(240),
  severity: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
  description: z.string().max(10000).default(''),
  assigned_to: z.string().max(120).optional(),
});

export const incidentStatusSchema = z.object({
  status: z.enum(['New', 'Open', 'Investigating', 'Contained', 'Resolved', 'Closed']),
});

export const incidentCommentSchema = z.object({ body: z.string().min(1).max(5000) });
export const savedSearchSchema = z.object({ name: z.string().min(1).max(200), query: z.record(z.any()) });
export const DASHBOARD_WIDGET_TYPES = [
  'total_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'low_alerts', 'alert_trend', 'severity_distribution',
  'top_agents', 'top_rules', 'top_srcips', 'top_dstips', 'recent_alerts', 'agent_inventory', 'agent_status', 'event_trends',
];
const dashboardWidgetSchema = z.object({
  widget_type: z.enum(DASHBOARD_WIDGET_TYPES),
  title: z.string().max(120).optional().nullable(),
  width: z.number().int().min(1).max(4).default(1),
  height: z.number().int().min(1).max(3).default(1),
  config: z.record(z.any()).default({}),
});
const dashboardFields = {
  name: z.string().trim().min(1).max(200),
  description: z.string().max(1000).optional(),
  layout: z.record(z.any()).default({}),
  is_default: z.boolean().optional(),
  widgets: z.array(dashboardWidgetSchema).max(40).optional(),
};
export const dashboardSchema = z.object(dashboardFields);
export const dashboardUpdateSchema = z.object({ ...dashboardFields, layout: z.record(z.any()) }).partial();

const csvList = (item) => z.preprocess(
  (value) => (value == null || value === '' ? [] : Array.isArray(value) ? value : String(value).split(','))
    .map((entry) => String(entry).trim()).filter(Boolean),
  z.array(item).max(50),
);
export const eventFilterSchema = z.object({
  from: z.string().datetime({ offset: true }).optional(),
  to: z.string().datetime({ offset: true }).optional(),
  minutes: z.coerce.number().int().min(1).max(576000).optional(),
  q: z.string().max(500).default(''),
  severity: csvList(z.enum(['critical', 'high', 'medium', 'low'])),
  agent: csvList(z.string().max(120)),
  rule_id: csvList(z.string().regex(/^\d{1,10}$/, 'Rule IDs are numeric')),
  srcip: csvList(z.string().regex(/^[0-9a-fA-F:.*]{1,64}$/, 'Invalid source IP')),
  dstip: csvList(z.string().regex(/^[0-9a-fA-F:.*]{1,64}$/, 'Invalid destination IP')),
  source: z.enum(['alerts', 'archives']).default('alerts'),
});
export const notificationRuleSchema = z.object({
  name: z.string().min(1).max(200),
  condition: z.record(z.any()),
  channel_id: z.number().int().positive().optional(),
  enabled: z.boolean().default(true),
});
