import * as siemService from '../services/siem.service.js';
import { config } from '../config/index.js';
import { eventCsvHeader, eventCsvRow } from '../utils/csv.js';
import { moduleIndexPatterns } from '../constants/index-patterns.js';
import { validate } from '../validators/validate.js';
import {
  agentOperationSchema, dashboardSchema, dashboardUpdateSchema, eventFilterSchema, incidentCommentSchema, incidentCreateSchema,
  incidentStatusSchema, indexOperationSchema, notificationRuleSchema, savedSearchSchema,
} from '../validators/api.validator.js';
import { parseTimeRange } from '../utils/time-range.js';

const bounded = (value, fallback, max) => Math.min(max, Math.max(1, Number(value || fallback)));
const recordId = (value) => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw Object.assign(new Error('Invalid identifier'), { status: 422 });
  return parsed;
};

/** Shared alert filters: from/to | minutes | hours, plus severity/agent/rule/IP filters (comma-separated). */
function eventFilters(query) {
  const filters = validate(eventFilterSchema, query);
  return {
    range: parseTimeRange({ from: filters.from, to: filters.to, minutes: filters.minutes, hours: query.hours ? bounded(query.hours, 24, 720) : undefined }),
    q: filters.q,
    severity: filters.severity,
    agent: filters.agent,
    ruleId: filters.rule_id,
    srcip: filters.srcip,
    dstip: filters.dstip,
    source: filters.source,
  };
}

export async function dashboard(req, res) {
  const { range, source: _source, ...filters } = eventFilters(req.query);
  res.json(await siemService.getDashboard(range, filters));
}

export async function events(req, res) {
  res.json(await siemService.getEvents({
    page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
    size: bounded(req.query.size, 50, 500),
    sort: req.query.sort,
    order: req.query.order === 'asc' ? 'asc' : 'desc',
    ...eventFilters(req.query),
  }));
}

async function writeCsvChunk(res, chunk) {
  if (res.destroyed) return false;
  if (res.write(chunk)) return true;
  await new Promise((resolve) => {
    const finish = () => {
      res.off('drain', finish);
      res.off('close', finish);
      resolve();
    };
    res.once('drain', finish);
    res.once('close', finish);
  });
  return !res.destroyed;
}

export async function exportEvents(req, res) {
  const filters = eventFilters(req.query);
  const iterator = siemService.scrollEvents({
    ...filters,
    sort: req.query.sort,
    order: req.query.order === 'asc' ? 'asc' : 'desc',
  });
  let iteratorDone = false;
  const nextBatch = async () => {
    const result = await iterator.next();
    iteratorDone = result.done;
    return result;
  };

  try {
    let batch = await nextBatch();
    res.status(200);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="security-events-${filters.range.gte.slice(0, 10)}_${filters.range.lte.slice(0, 10)}.csv"`);
    res.setHeader('Cache-Control', 'no-store');
    await writeCsvChunk(res, `\uFEFF${eventCsvHeader}\r\n`);

    while (!batch.done && !res.destroyed) {
      for (const event of batch.value) {
        if (!(await writeCsvChunk(res, `${eventCsvRow(event)}\r\n`))) break;
      }
      if (res.destroyed) break;
      batch = await nextBatch();
    }
    if (!res.destroyed) res.end();
  } catch (error) {
    if (res.headersSent) res.destroy();
    else throw error;
  } finally {
    if (!iteratorDone) await iterator.return().catch(() => {});
  }
}

const AGENT_STATUSES = ['active', 'disconnected', 'never_connected', 'pending'];
const agentParam = (value, pattern) => {
  const text = String(value ?? '').trim();
  return text && pattern.test(text) ? text : undefined;
};

export async function agents(req, res) {
  const statuses = String(req.query.status || '').split(',').filter((status) => AGENT_STATUSES.includes(status));
  res.json(await siemService.getAgents({
    page: bounded(req.query.page, 1, Number.MAX_SAFE_INTEGER),
    size: bounded(req.query.size, 100, 500),
    // `q` keeps the Wazuh query-language passthrough; `exclude_manager` hides agent 000 (the manager).
    q: req.query.exclude_manager === 'true' ? ['id!=000', req.query.q].filter(Boolean).join(';') : req.query.q,
    search: agentParam(req.query.search, /^[\w .:@-]{1,120}$/),
    status: statuses.join(',') || undefined,
    group: agentParam(req.query.group, /^[\w.-]{1,120}$/),
    platform: agentParam(req.query.platform, /^[\w.-]{1,60}$/),
    sort: req.query.sort,
    order: req.query.order === 'desc' ? 'desc' : 'asc',
  }));
}

export async function agentSummary(_req, res) {
  res.json(await siemService.getAgentSummary());
}

export async function agentDetail(req, res) {
  const id = String(req.params.id);
  if (!/^\d{3,8}$/.test(id)) return res.status(422).json({ error: 'Invalid agent identifier' });
  res.json(await siemService.getAgent(id));
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
  res.status(201).json(await siemService.saveSearch(req.user.id, body.name, body.query, body.module));
}

export async function savedSearches(req, res) {
  const module = /^[a-z0-9_]{1,40}$/.test(String(req.query.module || '')) ? String(req.query.module) : undefined;
  res.json(await siemService.getSavedSearches(req.user.id, module));
}

export async function deleteSavedSearch(req, res) {
  if (!(await siemService.deleteSavedSearch(req.user.id, recordId(req.params.id)))) return res.status(404).json({ error: 'Saved search not found' });
  res.status(204).end();
}

export async function dashboards(req, res) {
  res.json(await siemService.getDashboards(req.user.id));
}

export async function savedDashboard(req, res) {
  const dashboard = await siemService.getSavedDashboard(req.user.id, recordId(req.params.id));
  if (!dashboard) return res.status(404).json({ error: 'Dashboard not found' });
  res.json(dashboard);
}

export async function saveDashboard(req, res) {
  const body = validate(dashboardSchema, req.body);
  res.status(201).json(await siemService.saveDashboard(req.user.id, body, req.user));
}

export async function updateDashboard(req, res) {
  const body = validate(dashboardUpdateSchema, req.body);
  res.json(await siemService.updateDashboard(req.user.id, recordId(req.params.id), body, req.user));
}

export async function deleteDashboard(req, res) {
  await siemService.deleteDashboard(req.user.id, recordId(req.params.id), req.user);
  res.status(204).end();
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
