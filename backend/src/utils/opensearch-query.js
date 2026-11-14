import { SEVERITY_LEVELS } from '../constants/severity.js';

// Field names follow the Wazuh 4.x alerts index template (all keyword fields, no `.keyword` sub-fields).
export const ALERT_FIELDS = {
  timestamp: '@timestamp',
  level: 'rule.level',
  ruleId: 'rule.id',
  ruleDescription: 'rule.description',
  ruleGroups: 'rule.groups',
  agentId: 'agent.id',
  agentName: 'agent.name',
  srcip: 'data.srcip',
  dstip: 'data.dstip',
};

const toList = (value) => (Array.isArray(value) ? value : value == null || value === '' ? [] : String(value).split(','))
  .map((item) => String(item).trim()).filter(Boolean).slice(0, 50);

function valueClause(field, values) {
  const exact = values.filter((value) => !value.includes('*'));
  const patterns = values.filter((value) => value.includes('*'));
  const should = [];
  if (exact.length) should.push({ terms: { [field]: exact } });
  for (const pattern of patterns) should.push({ wildcard: { [field]: { value: pattern, case_insensitive: true } } });
  return should.length === 1 ? should[0] : { bool: { should, minimum_should_match: 1 } };
}

/**
 * Build an OpenSearch bool query for Wazuh alerts.
 * filters: { range: {gte,lte}, q, severity[], agent[], ruleId[], srcip[], dstip[], ruleGroups[], minLevel, extra[] }
 */
export function buildAlertQuery(filters = {}) {
  const filter = [];
  const must = [];

  if (filters.range) {
    filter.push({ range: { [ALERT_FIELDS.timestamp]: { gte: filters.range.gte, lte: filters.range.lte, format: 'strict_date_optional_time' } } });
  }

  const severities = toList(filters.severity).filter((name) => SEVERITY_LEVELS[name]);
  if (severities.length) {
    filter.push({ bool: { should: severities.map((name) => ({ range: { [ALERT_FIELDS.level]: SEVERITY_LEVELS[name] } })), minimum_should_match: 1 } });
  }
  if (Number.isFinite(Number(filters.minLevel)) && filters.minLevel !== '' && filters.minLevel != null) {
    filter.push({ range: { [ALERT_FIELDS.level]: { gte: Number(filters.minLevel) } } });
  }

  const agents = toList(filters.agent);
  if (agents.length) {
    const ids = agents.filter((value) => /^\d{3,8}$/.test(value));
    const names = agents.filter((value) => !/^\d{3,8}$/.test(value));
    const should = [];
    if (ids.length) should.push({ terms: { [ALERT_FIELDS.agentId]: ids } });
    if (names.length) should.push(valueClause(ALERT_FIELDS.agentName, names));
    filter.push({ bool: { should, minimum_should_match: 1 } });
  }

  const ruleIds = toList(filters.ruleId);
  if (ruleIds.length) filter.push({ terms: { [ALERT_FIELDS.ruleId]: ruleIds } });

  const srcips = toList(filters.srcip);
  if (srcips.length) filter.push(valueClause(ALERT_FIELDS.srcip, srcips));

  const dstips = toList(filters.dstip);
  if (dstips.length) filter.push(valueClause(ALERT_FIELDS.dstip, dstips));

  const groups = toList(filters.ruleGroups);
  if (groups.length) filter.push({ terms: { [ALERT_FIELDS.ruleGroups]: groups } });

  if (Array.isArray(filters.extra)) filter.push(...filters.extra);

  const q = String(filters.q || '').trim().slice(0, 500);
  if (q) must.push({ simple_query_string: { query: q, default_operator: 'and', lenient: true } });

  return { bool: { filter, ...(must.length ? { must } : {}) } };
}

/** Convert `field:asc` style or separate sort/order params into an OpenSearch sort clause. */
export function buildSort(sort, order, allowed) {
  const field = allowed.includes(sort) ? sort : allowed[0];
  return [{ [field]: { order: order === 'asc' ? 'asc' : 'desc', unmapped_type: 'keyword' } }];
}

export const mapHits = (hits) => hits.map((hit) => ({ ...hit._source, _id: hit._id, _index: hit._index }));
