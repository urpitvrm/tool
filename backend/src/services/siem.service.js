import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import { opensearch, wazuh } from '../services/integration.service.js';
import * as siemModel from '../models/siem.model.js';
import * as dashboardModel from '../models/dashboard.model.js';
import { SEVERITY_LEVELS } from '../constants/severity.js';
import { buildAlertQuery, buildSort, mapHits } from '../utils/opensearch-query.js';
import { histogramInterval, parseTimeRange } from '../utils/time-range.js';

// OpenSearch only pages through the first `index.max_result_window` hits (10,000 by default).
const MAX_RESULT_WINDOW = 10_000;
const EVENT_SORT_FIELDS = ['@timestamp', 'rule.level', 'agent.name', 'rule.id'];
const severityRanges = Object.entries(SEVERITY_LEVELS)
  .map(([key, range]) => ({ key, from: range.gte, ...(range.lte != null ? { to: range.lte + 1 } : {}) }));
const terms = (field, size = 10) => ({ terms: { field, size } });

/** Resolve which index a security-event search targets. Only configured indices are allowed. */
export function eventIndex(source) {
  if (source === 'archives') {
    if (!config.archivesIndex) {
      throw Object.assign(new Error('The archives index is not configured (OPENSEARCH_ARCHIVES_INDEX).'), { status: 422 });
    }
    return config.archivesIndex;
  }
  return config.eventsIndex;
}

/**
 * Aggregated dashboard data in a single OpenSearch request.
 * Accepts the legacy `hours` number or a resolved time range.
 */
export async function getDashboard(rangeOrHours, filters = {}) {
  const range = typeof rangeOrHours === 'object' ? rangeOrHours : parseTimeRange({ hours: rangeOrHours });
  const interval = histogramInterval(range);
  const histogram = { field: '@timestamp', fixed_interval: interval, min_doc_count: 0, extended_bounds: { min: range.gte, max: range.lte } };
  const result = await opensearch().search({ index: config.eventsIndex, body: {
    size: 10,
    track_total_hits: true,
    sort: [{ '@timestamp': { order: 'desc' } }],
    _source: ['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'rule.groups', 'agent.id', 'agent.name', 'data.srcip', 'data.dstip'],
    query: buildAlertQuery({ ...filters, range }),
    aggs: {
      severity: terms('rule.level', 16),
      severity_summary: { range: { field: 'rule.level', ranges: severityRanges } },
      timeline: { date_histogram: histogram, aggs: { severity: { range: { field: 'rule.level', ranges: severityRanges } } } },
      agents: terms('agent.name'),
      rules: terms('rule.description'),
      top_rules: { terms: { field: 'rule.id', size: 10 }, aggs: { description: terms('rule.description', 1), level: { max: { field: 'rule.level' } } } },
      top_srcips: terms('data.srcip'),
      top_dstips: terms('data.dstip'),
      event_trends: { terms: { field: 'rule.groups', size: 5 }, aggs: { timeline: { date_histogram: histogram } } },
    },
  } });
  const data = result.body;
  const aggs = data.aggregations;
  const bandCounts = (buckets) => Object.fromEntries(buckets.map((bucket) => [bucket.key, bucket.doc_count]));
  return {
    range: { from: range.gte, to: range.lte, interval },
    total_events: data.hits.total?.value || 0,
    severity: aggs.severity.buckets,
    severity_summary: bandCounts(aggs.severity_summary.buckets),
    timeline: aggs.timeline.buckets.map((bucket) => ({
      key: bucket.key, key_as_string: bucket.key_as_string, doc_count: bucket.doc_count, ...bandCounts(bucket.severity.buckets),
    })),
    agents: aggs.agents.buckets,
    rules: aggs.rules.buckets,
    top_rules: aggs.top_rules.buckets.map((bucket) => ({
      key: bucket.key, doc_count: bucket.doc_count, description: bucket.description.buckets[0]?.key || '', level: bucket.level.value,
    })),
    top_srcips: aggs.top_srcips.buckets,
    top_dstips: aggs.top_dstips.buckets,
    event_trends: aggs.event_trends.buckets.map((group) => ({
      key: group.key, doc_count: group.doc_count,
      timeline: group.timeline.buckets.map((bucket) => ({ key: bucket.key, doc_count: bucket.doc_count })),
    })),
    recent: mapHits(data.hits.hits),
  };
}

export async function getEvents({ page, size, hours, range, q, sort, order, source, ...filters }) {
  if ((page - 1) * size + size > MAX_RESULT_WINDOW) {
    throw Object.assign(new Error(`Only the first ${MAX_RESULT_WINDOW.toLocaleString('en-US')} results can be paged. Narrow the time range or filters.`), { status: 422 });
  }
  const resolved = range || parseTimeRange({ hours });
  const { body } = await opensearch().search({ index: eventIndex(source), body: {
    from: (page - 1) * size, size, track_total_hits: true,
    sort: buildSort(sort, order, EVENT_SORT_FIELDS),
    query: buildAlertQuery({ ...filters, q, range: resolved }),
  } });
  return { total: body.hits.total?.value || 0, page, size, max_window: MAX_RESULT_WINDOW, items: mapHits(body.hits.hits) };
}

/** Async iterator over every matching event (scroll API), yielded in batches. */
export async function* scrollEvents({ hours, range, q, sort = '@timestamp', order = 'desc', source, limit = Infinity, batchSize = 1000, ...filters }) {
  const query = buildAlertQuery({ ...filters, q, range: range || parseTimeRange({ hours }) });
  const client = opensearch();
  let scrollId;
  let emitted = 0;

  try {
    let response = await client.search({
      index: eventIndex(source),
      scroll: '1m',
      body: { size: Math.min(batchSize, limit), sort: buildSort(sort, order, EVENT_SORT_FIELDS), query },
    });
    scrollId = response.body._scroll_id;

    while (response.body.hits.hits.length && emitted < limit) {
      const batch = mapHits(response.body.hits.hits).slice(0, limit - emitted);
      emitted += batch.length;
      yield batch;
      if (!scrollId || emitted >= limit) break;
      response = await client.scroll({ scroll_id: scrollId, scroll: '1m' });
      scrollId = response.body._scroll_id || scrollId;
    }
  } finally {
    if (scrollId) await client.clearScroll({ scroll_id: scrollId }).catch(() => {});
  }
}

export const AGENT_SORT_FIELDS = ['id', 'name', 'ip', 'status', 'version', 'os.name', 'os.platform', 'lastKeepAlive', 'dateAdd', 'group'];

export async function getAgents({ page, size, q, search, status, group, platform, sort, order }) {
  const params = {
    limit: size,
    offset: (page - 1) * size,
    q: q || undefined,
    search: search || undefined,
    status: status || undefined,
    group: group || undefined,
    'os.platform': platform || undefined,
    sort: AGENT_SORT_FIELDS.includes(sort) ? `${order === 'desc' ? '-' : '+'}${sort}` : undefined,
  };
  const data = (await wazuh('/agents', { params })).data?.data || {};
  return { total: data.total_affected_items || 0, page, size, items: data.affected_items || [] };
}

export async function getAgent(id) {
  const data = (await wazuh('/agents', { params: { agents_list: id } })).data?.data || {};
  const agent = data.affected_items?.[0];
  if (!agent) throw Object.assign(new Error('Agent not found'), { status: 404 });
  return agent;
}

/** Fetch the complete agent inventory, paging through the Wazuh API. */
export async function getAllAgents(params = {}) {
  const items = [];
  const limit = 500;
  for (let offset = 0; ; offset += limit) {
    const data = (await wazuh('/agents', { params: { ...params, limit, offset } })).data?.data || {};
    const page = data.affected_items || [];
    items.push(...page);
    if (!page.length || items.length >= (data.total_affected_items || 0)) break;
  }
  return items;
}

/** Agent connection-status counts (Wazuh 4.x) plus OS platform distribution. */
export async function getAgentSummary() {
  const [statusResponse, platformResponse] = await Promise.all([
    wazuh('/agents/summary/status'),
    wazuh('/agents/stats/distinct', { params: { fields: 'os.platform' } }).catch(() => null),
  ]);
  const raw = statusResponse.data?.data || {};
  const status = raw.connection || raw; // Wazuh 4.4+ nests the counts under `connection`.
  return {
    total: status.total || 0,
    active: status.active || 0,
    disconnected: status.disconnected || 0,
    never_connected: status.never_connected || 0,
    pending: status.pending || 0,
    configuration: raw.configuration || null,
    platforms: (platformResponse?.data?.data?.affected_items || [])
      .map((item) => ({ key: item.os?.platform || 'unknown', doc_count: item.count })),
  };
}

export async function getAgentGroups() {
  const data = (await wazuh('/groups')).data?.data || {};
  return { total: data.total_affected_items || 0, items: data.affected_items || [] };
}

export async function operateAgent(id, operation, user) {
  const response = operation === 'restart'
    ? await wazuh(`/agents/${id}/restart`, { method: 'PUT' })
    : await wazuh('/agents', { method: 'DELETE', params: { agents_list: id } });
  await audit(user, 'agent.operation', { agent_id: id, operation });
  return { completed: true, result: response.data };
}

export async function getIndices() {
  return (await opensearch().cat.indices({ format: 'json', h: 'health,status,index,docs.count,store.size,pri,rep' })).body;
}

export async function getIndexMappings(name) {
  return (await opensearch().indices.getMapping({ index: name })).body;
}

export async function searchIndex(name, { page, size, q }) {
  const result = await opensearch().search({ index: name, body: {
    from: (page - 1) * size, size,
    query: q ? { simple_query_string: { query: q, default_operator: 'and' } } : { match_all: {} },
  } });
  return { total: result.body.hits.total?.value || 0, page, size,
    items: result.body.hits.hits.map((hit) => ({ ...hit._source, _id: hit._id })) };
}

export async function operateIndex(name, operation, user) {
  const indices = opensearch().indices;
  if (operation === 'delete') await indices.delete({ index: name });
  else if (operation === 'refresh') await indices.refresh({ index: name });
  else if (operation === 'flush') await indices.flush({ index: name });
  else if (operation === 'open') await indices.open({ index: name });
  else await indices.close({ index: name });
  await audit(user, 'index.operation', { index: name, operation });
  return { completed: true, operation, index: name };
}

export async function getClusterHealth() {
  return (await opensearch().cluster.health()).body;
}

export async function listIncidents() {
  return siemModel.listIncidents();
}

export async function createIncident(body, user) {
  const incident = await siemModel.createIncident({ ...body, assignedTo: body.assigned_to, userId: user.id });
  await audit(user, 'incident.create', { id: incident.id });
  return incident;
}

export async function updateIncident(id, status, user) {
  const incident = await siemModel.updateIncidentStatus(id, status);
  if (incident) await audit(user, 'incident.update', { id, status });
  return incident;
}

export async function addIncidentComment(id, body, user) {
  const comment = await siemModel.addIncidentComment(id, user.id, body);
  await audit(user, 'incident.comment', { id });
  return comment;
}

export async function getAuditLogs(page, size) {
  return siemModel.listAuditLogs(page, size);
}

export async function getModuleData(module, index, { page, size, hours, q }) {
  const body = { from: (page - 1) * size, size, query: { bool: {
    filter: [{ range: { '@timestamp': { gte: `now-${hours}h`, format: 'epoch_millis||strict_date_optional_time' } } }],
    ...(q ? { must: [{ simple_query_string: { query: q, default_operator: 'and' } }] } : {}),
  } } };
  const result = await opensearch().search({ index, body });
  return { source: 'opensearch', index, total: result.body.hits.total?.value || 0, page, size,
    items: result.body.hits.hits.map((hit) => ({ ...hit._source, _id: hit._id })) };
}

export const saveSearch = (userId, name, query, module) => siemModel.upsertSavedSearch(userId, name, query, module);
export const getSavedSearches = (userId, module) => siemModel.listSavedSearches(userId, module);
export const deleteSavedSearch = (userId, id) => siemModel.deleteSavedSearch(userId, id);
export const getDashboards = (userId) => dashboardModel.listDashboards(userId);
export const getSavedDashboard = (userId, id) => dashboardModel.findDashboard(userId, id);

export async function saveDashboard(userId, body, user) {
  const dashboard = await dashboardModel.createDashboard(userId, body);
  if (user) await audit(user, 'dashboard.create', { id: dashboard.id, name: dashboard.name });
  return dashboard;
}

export async function updateDashboard(userId, id, body, user) {
  const dashboard = await dashboardModel.updateDashboard(userId, id, body);
  if (!dashboard) throw Object.assign(new Error('Dashboard not found'), { status: 404 });
  await audit(user, 'dashboard.update', { id });
  return dashboard;
}

export async function deleteDashboard(userId, id, user) {
  if (!(await dashboardModel.deleteDashboard(userId, id))) throw Object.assign(new Error('Dashboard not found'), { status: 404 });
  await audit(user, 'dashboard.delete', { id });
}

export const getNotificationRules = () => siemModel.listNotificationRules();

export async function createNotificationRule(body, user) {
  const rule = await siemModel.createNotificationRule({ ...body, channelId: body.channel_id });
  await audit(user, 'notification.rule_create', { id: rule.id });
  return rule;
}

export const getSettings = () => siemModel.listSettings();

export async function saveSetting(key, value, user) {
  await siemModel.upsertSetting(key, value);
  await audit(user, 'settings.update', { key });
}
