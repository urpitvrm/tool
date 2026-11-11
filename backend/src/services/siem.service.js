import { config } from '../config/index.js';
import { audit } from '../config/db.js';
import { opensearch, wazuh } from '../services/integration.service.js';
import * as siemModel from '../models/siem.model.js';
import { openSearchClient } from '../services/integration.service.js';

// Example usage
const client = openSearchClient();
export async function getDashboard(hours) {
  const result = await client.search({ index: config.eventsIndex, body: {
    size: 0,
    query: { range: { '@timestamp': { gte: `now-${hours}h` } } },
    aggs: {
      severity: { terms: { field: 'rule.level', size: 10 } },
      timeline: { date_histogram: { field: '@timestamp', fixed_interval: '1h' } },
      agents: { terms: { field: 'agent.name.keyword', size: 10 } },
      rules: { terms: { field: 'rule.description.keyword', size: 10 } },
    },
  } });
  const data = result.body;
  return { total_events: data.hits.total?.value || 0, severity: data.aggregations.severity.buckets,
    timeline: data.aggregations.timeline.buckets, agents: data.aggregations.agents.buckets, rules: data.aggregations.rules.buckets };
}

export async function getEvents({ page, size, hours, q, sort, order }) {
  const query = { bool: { filter: [{ range: { '@timestamp': { gte: `now-${hours}h` } } }],
    ...(q ? { must: [{ simple_query_string: { query: q, default_operator: 'and' } }] } : {}) } };
  const { body } = await opensearch().search({ index: config.eventsIndex, body: {
    from: (page - 1) * size, size, sort: [{ [sort]: { order, unmapped_type: 'keyword' } }], query,
  } });
  return { total: body.hits.total?.value || 0, page, size,
    items: body.hits.hits.map((hit) => ({ ...hit._source, _id: hit._id })) };
}

export async function getAgents({ page, size, q }) {
  const offset = (page - 1) * size;
  const data = (await wazuh('/agents', { params: { limit: size, offset, q: q || undefined } })).data?.data || {};
  return { total: data.total_affected_items || 0, page, size, items: data.affected_items || [] };
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

export const saveSearch = (userId, name, query) => siemModel.upsertSavedSearch(userId, name, query);
export const getSavedSearches = (userId) => siemModel.listSavedSearches(userId);
export const getDashboards = (userId) => siemModel.listDashboards(userId);
export const saveDashboard = (userId, name, layout) => siemModel.createDashboard(userId, name, layout);
export const getReportHistory = () => siemModel.listReportHistory();
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
