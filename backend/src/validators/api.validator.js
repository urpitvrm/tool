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
export const dashboardSchema = z.object({ name: z.string().min(1).max(200), layout: z.record(z.any()).default({}) });
export const notificationRuleSchema = z.object({
  name: z.string().min(1).max(200),
  condition: z.record(z.any()),
  channel_id: z.number().int().positive().optional(),
  enabled: z.boolean().default(true),
});
