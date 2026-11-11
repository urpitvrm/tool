import * as siemService from '../services/siem.service.js';
import { config } from '../config/index.js';
import { moduleIndexPatterns } from '../constants/index-patterns.js';
import { validate } from '../validators/validate.js';
import {
  agentOperationSchema, dashboardSchema, incidentCommentSchema, incidentCreateSchema,
  incidentStatusSchema, indexOperationSchema, notificationRuleSchema, savedSearchSchema,
} from '../validators/api.validator.js';

const bounded = (value, fallback, max) => Math.min(max, Math.max(1, Number(value || fallback)));

export async function dashboard(req, res) {
  res.json(await siemService.getDashboard(bounded(req.query.hours, 24, 720)));
}

export async function events(req, res) {
  const allowedSort = ['@timestamp', 'rule.level', 'agent.name', 'rule.id'];
  const sort = allowedSort.includes(req.query.sort) ? req.query.sort : '@timestamp';
  res.json(await siemService.getEvents({
    page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
    size: bounded(req.query.size, 50, 500),
    hours: bounded(req.query.hours, 24, 720),
    q: String(req.query.q || '').slice(0, 500),
    sort,
    order: req.query.order === 'asc' ? 'asc' : 'desc',
  }));
}

export async function agents(req, res) {
  res.json(await siemService.getAgents({
    page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
    size: bounded(req.query.size, 100, 500),
    q: req.query.q,
  }));
}

export async function agentGroups(_req, res) {
  res.json(await siemService.getAgentGroups());
}

export async function agentOperation(req, res) {
  const id = String(req.params.id);
  if (!/^\d{1,8}$/.test(id)) return res.status(422).json({ error: 'Invalid agent identifier' });
  const { operation, confirm } = validate(agentOperationSchema, req.body);
  if (!confirm) return res.status(422).json({ error: 'Confirmation is required' });
  res.json(await siemService.operateAgent(id, operation, req.user));
}

export async function indices(_req, res) {
  res.json(await siemService.getIndices());
}

export async function indexMappings(req, res) {
  res.json(await siemService.getIndexMappings(req.params.name));
}

export async function indexSearch(req, res) {
  res.json(await siemService.searchIndex(req.params.name, {
    page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
    size: bounded(req.query.size, 50, 200),
    q: String(req.query.q || '').slice(0, 500),
  }));
}

export async function indexOperation(req, res) {
  const name = String(req.params.name);
  if (!/^[a-z0-9][a-z0-9._-]{0,254}$/.test(name)) return res.status(422).json({ error: 'Invalid index name' });
  const { operation, confirm } = validate(indexOperationSchema, req.body);
  if (!confirm) return res.status(422).json({ error: 'Confirmation is required' });
  res.json(await siemService.operateIndex(name, operation, req.user));
}

export async function clusterHealth(_req, res) {
  res.json(await siemService.getClusterHealth());
}

export async function incidents(_req, res) {
  res.json(await siemService.listIncidents());
}

export async function createIncident(req, res) {
  const body = validate(incidentCreateSchema, req.body);
  res.status(201).json(await siemService.createIncident(body, req.user));
}

export async function updateIncident(req, res) {
  const { status } = validate(incidentStatusSchema, req.body);
  const incident = await siemService.updateIncident(req.params.id, status, req.user);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  res.json(incident);
}

export async function incidentComment(req, res) {
  const { body } = validate(incidentCommentSchema, req.body);
  res.status(201).json(await siemService.addIncidentComment(req.params.id, body, req.user));
}

export async function auditLogs(req, res) {
  res.json(await siemService.getAuditLogs(
    bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER), bounded(req.query.size, 100, 500),
  ));
}

export function moduleData(module) {
  const patterns = moduleIndexPatterns(config.eventsIndex);
  return async (req, res) => {
    res.json(await siemService.getModuleData(module, patterns[module], {
      page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
      size: bounded(req.query.size, 50, 200),
      hours: bounded(req.query.hours, 168, 720),
      q: String(req.query.q || '').slice(0, 300),
    }));
  };
}

export async function saveSearch(req, res) {
  const body = validate(savedSearchSchema, req.body);
  res.status(201).json(await siemService.saveSearch(req.user.id, body.name, body.query));
}

export async function savedSearches(req, res) {
  res.json(await siemService.getSavedSearches(req.user.id));
}

export async function dashboards(req, res) {
  res.json(await siemService.getDashboards(req.user.id));
}

export async function saveDashboard(req, res) {
  const body = validate(dashboardSchema, req.body);
  res.status(201).json(await siemService.saveDashboard(req.user.id, body.name, body.layout));
}

export async function reportHistory(_req, res) {
  res.json(await siemService.getReportHistory());
}

export async function notificationRules(_req, res) {
  res.json(await siemService.getNotificationRules());
}

export async function createNotificationRule(req, res) {
  const body = validate(notificationRuleSchema, req.body);
  res.status(201).json(await siemService.createNotificationRule(body, req.user));
}

export async function settings(_req, res) {
  res.json(await siemService.getSettings());
}

export async function updateSetting(req, res) {
  await siemService.saveSetting(req.params.key, req.body.value, req.user);
  res.json({ saved: true });
}

export function activeResponse(_req, res) {
  res.status(501).json({ error: 'Active response requires an explicitly supported and configured Manager operation.' });
}
