import { config } from '../config/index.js';
import { opensearch } from './integration.service.js';
import { getAgentSummary, getAllAgents, scrollEvents } from './siem.service.js';
import { REPORT_TYPES, columnValue } from '../constants/report-types.js';
import { SEVERITY_LEVELS, SEVERITY_NAMES } from '../constants/severity.js';
import { buildAlertQuery } from '../utils/opensearch-query.js';
import { histogramInterval } from '../utils/time-range.js';

const severityRanges = Object.entries(SEVERITY_LEVELS)
  .map(([key, range]) => ({ key, from: range.gte, ...(range.lte != null ? { to: range.lte + 1 } : {}) }));
const terms = (field, size = 10) => ({ terms: { field, size } });
const countRows = (buckets, label) => buckets.map((bucket, index) => ({ rank: index + 1, [label]: bucket.key, count: bucket.doc_count }));
const rankColumns = (label, title) => [{ key: 'rank', label: '#', weight: 0.3 }, { key: label, label: title, weight: 3 }, { key: 'count', label: 'Alerts', weight: 0.8 }];

/** Merge base, default and user filters for a report type. */
export function effectiveFilters(type, userFilters = {}) {
  const merged = { ...userFilters };
  for (const [key, value] of Object.entries(type.defaultFilters || {})) {
    const current = merged[key];
    if (current == null || (Array.isArray(current) && !current.length) || current === '') merged[key] = value;
  }
  return { ...merged, ...(type.baseFilters || {}) };
}

function selectedColumns(type, keys) {
  const catalog = type.columns || [];
  const wanted = Array.isArray(keys) && keys.length ? keys : type.defaultColumns || [];
  const columns = wanted.map((key) => catalog.find((column) => column.key === key)).filter(Boolean);
  return columns.length ? columns : catalog.slice(0, 8);
}

function alertAggregations(type, range) {
  const aggs = {};
  const sections = new Set(type.sections);
  aggs.severity = { range: { field: 'rule.level', ranges: severityRanges } };
  aggs.agent_count = { cardinality: { field: 'agent.id' } };
  aggs.rule_count = { cardinality: { field: 'rule.id' } };
  if (sections.has('timeline')) aggs.timeline = { date_histogram: { field: '@timestamp', fixed_interval: histogramInterval(range), min_doc_count: 0, extended_bounds: { min: range.gte, max: range.lte } } };
  if (sections.has('top_agents')) aggs.top_agents = terms('agent.name');
  if (sections.has('top_rules')) aggs.top_rules = { terms: { field: 'rule.id', size: 10 }, aggs: { description: terms('rule.description', 1), level: { max: { field: 'rule.level' } } } };
  if (sections.has('top_srcips')) aggs.top_srcips = terms('data.srcip');
  if (sections.has('top_dstips')) aggs.top_dstips = terms('data.dstip');
  if (sections.has('top_users')) aggs.top_users = terms('data.srcuser');
  if (sections.has('auth_outcomes')) {
    aggs.auth_outcomes = { filters: { filters: {
      success: { terms: { 'rule.groups': ['authentication_success'] } },
      failure: { terms: { 'rule.groups': ['authentication_failed', 'authentication_failures', 'invalid_login', 'win_authentication_failed'] } },
    } } };
  }
  if (sections.has('vuln_severity')) aggs.vuln_severity = terms('data.vulnerability.severity');
  if (sections.has('top_cves')) aggs.top_cves = { terms: { field: 'data.vulnerability.cve', size: 15 }, aggs: { title: terms('data.vulnerability.title', 1), severity: terms('data.vulnerability.severity', 1), agents: { cardinality: { field: 'agent.id' } } } };
  if (sections.has('top_packages')) aggs.top_packages = terms('data.vulnerability.package.name', 15);
  if (sections.has('rule_distribution')) {
    aggs.rule_distribution = { terms: { field: 'rule.id', size: 500 }, aggs: {
      description: terms('rule.description', 1), level: { max: { field: 'rule.level' } }, groups: terms('rule.groups', 3),
      agents: { cardinality: { field: 'agent.id' } }, first_seen: { min: { field: '@timestamp' } }, last_seen: { max: { field: '@timestamp' } },
    } };
  }
  if (sections.has('attacking_ips')) {
    aggs.attacking_ips = { terms: { field: 'data.srcip', size: 100 }, aggs: {
      max_level: { max: { field: 'rule.level' } }, agents: { cardinality: { field: 'agent.id' } }, rules: { cardinality: { field: 'rule.id' } },
      top_rule: terms('rule.description', 1), first_seen: { min: { field: '@timestamp' } }, last_seen: { max: { field: '@timestamp' } },
    } };
  }
  return aggs;
}

async function buildAlertSections(type, range, filters, document) {
  const query = buildAlertQuery({ ...filters, range, extra: type.extraQuery });
  const response = await opensearch().search({
    index: config.eventsIndex,
    body: { size: 0, track_total_hits: true, query, aggs: alertAggregations(type, range) },
  });
  const { aggregations: aggs, hits } = response.body;
  const total = hits.total?.value || 0;
  const bands = Object.fromEntries(aggs.severity.buckets.map((bucket) => [bucket.key, bucket.doc_count]));

  document.kpis.push(
    { label: 'Total alerts', value: total },
    { label: 'Critical', value: bands.critical || 0, tone: 'critical' },
    { label: 'High', value: bands.high || 0, tone: 'high' },
    { label: 'Medium', value: bands.medium || 0, tone: 'medium' },
    { label: 'Low', value: bands.low || 0, tone: 'low' },
    { label: 'Agents reporting', value: aggs.agent_count.value || 0 },
    { label: 'Distinct rules', value: aggs.rule_count.value || 0 },
  );

  for (const section of type.sections) {
    if (section === 'severity') {
      document.sections.push({ title: 'Severity distribution', chart: 'bar', labelKey: 'severity', valueKey: 'count',
        columns: [{ key: 'severity', label: 'Severity', weight: 1 }, { key: 'levels', label: 'Rule levels', weight: 1 }, { key: 'count', label: 'Alerts', weight: 1 }, { key: 'share', label: 'Share', weight: 1 }],
        rows: SEVERITY_NAMES.map((name) => ({
          severity: name, levels: SEVERITY_LEVELS[name].lte != null ? `${SEVERITY_LEVELS[name].gte}–${SEVERITY_LEVELS[name].lte}` : `${SEVERITY_LEVELS[name].gte}+`,
          count: bands[name] || 0, share: total ? `${(((bands[name] || 0) / total) * 100).toFixed(1)}%` : '0%',
        })) });
    } else if (section === 'timeline' && aggs.timeline) {
      document.sections.push({ title: 'Alert trend', chart: 'bar', labelKey: 'period', valueKey: 'count',
        columns: [{ key: 'period', label: 'Period start', weight: 2 }, { key: 'count', label: 'Alerts', weight: 1 }],
        rows: aggs.timeline.buckets.map((bucket) => ({ period: new Date(bucket.key).toISOString(), count: bucket.doc_count })) });
    } else if (section === 'top_agents' && aggs.top_agents) {
      document.sections.push({ title: 'Top agents', chart: 'bar', labelKey: 'agent', valueKey: 'count', columns: rankColumns('agent', 'Agent'), rows: countRows(aggs.top_agents.buckets, 'agent') });
    } else if (section === 'top_rules' && aggs.top_rules) {
      document.sections.push({ title: 'Top rules', columns: [{ key: 'rank', label: '#', weight: 0.3 }, { key: 'rule_id', label: 'Rule ID', weight: 0.7 }, { key: 'description', label: 'Description', weight: 3 }, { key: 'level', label: 'Level', weight: 0.5 }, { key: 'count', label: 'Alerts', weight: 0.7 }],
        rows: aggs.top_rules.buckets.map((bucket, index) => ({ rank: index + 1, rule_id: bucket.key, description: bucket.description.buckets[0]?.key || '', level: bucket.level.value, count: bucket.doc_count })) });
    } else if (section === 'top_srcips' && aggs.top_srcips) {
      document.sections.push({ title: 'Top source IP addresses', chart: 'bar', labelKey: 'ip', valueKey: 'count', columns: rankColumns('ip', 'Source IP'), rows: countRows(aggs.top_srcips.buckets, 'ip') });
    } else if (section === 'top_dstips' && aggs.top_dstips) {
      document.sections.push({ title: 'Top destination IP addresses', chart: 'bar', labelKey: 'ip', valueKey: 'count', columns: rankColumns('ip', 'Destination IP'), rows: countRows(aggs.top_dstips.buckets, 'ip') });
    } else if (section === 'top_users' && aggs.top_users) {
      document.sections.push({ title: 'Top source users', columns: rankColumns('user', 'User'), rows: countRows(aggs.top_users.buckets, 'user') });
    } else if (section === 'auth_outcomes' && aggs.auth_outcomes) {
      const buckets = aggs.auth_outcomes.buckets;
      document.sections.push({ title: 'Authentication outcomes', chart: 'bar', labelKey: 'outcome', valueKey: 'count',
        columns: [{ key: 'outcome', label: 'Outcome', weight: 1 }, { key: 'count', label: 'Events', weight: 1 }],
        rows: [{ outcome: 'Successful', count: buckets.success.doc_count }, { outcome: 'Failed', count: buckets.failure.doc_count }] });
    } else if (section === 'vuln_severity' && aggs.vuln_severity) {
      document.sections.push({ title: 'Vulnerabilities by severity', chart: 'bar', labelKey: 'severity', valueKey: 'count',
        columns: [{ key: 'severity', label: 'Severity', weight: 1 }, { key: 'count', label: 'Findings', weight: 1 }],
        rows: aggs.vuln_severity.buckets.map((bucket) => ({ severity: bucket.key, count: bucket.doc_count })) });
    } else if (section === 'top_cves' && aggs.top_cves) {
      document.sections.push({ title: 'Most frequent CVEs', columns: [{ key: 'cve', label: 'CVE', weight: 1 }, { key: 'severity', label: 'Severity', weight: 0.7 }, { key: 'title', label: 'Title', weight: 3 }, { key: 'agents', label: 'Agents', weight: 0.5 }, { key: 'count', label: 'Findings', weight: 0.6 }],
        rows: aggs.top_cves.buckets.map((bucket) => ({ cve: bucket.key, severity: bucket.severity.buckets[0]?.key || '', title: bucket.title.buckets[0]?.key || '', agents: bucket.agents.value, count: bucket.doc_count })) });
    } else if (section === 'top_packages' && aggs.top_packages) {
      document.sections.push({ title: 'Most affected packages', columns: rankColumns('package', 'Package'), rows: countRows(aggs.top_packages.buckets, 'package') });
    } else if (section === 'rule_distribution' && aggs.rule_distribution) {
      document.sections.push({ title: 'Rule distribution', primary: true,
        columns: [{ key: 'rule_id', label: 'Rule ID', weight: 0.6 }, { key: 'description', label: 'Description', weight: 3 }, { key: 'level', label: 'Level', weight: 0.4 }, { key: 'groups', label: 'Groups', weight: 1.4 }, { key: 'agents', label: 'Agents', weight: 0.5 }, { key: 'count', label: 'Alerts', weight: 0.6 }, { key: 'first_seen', label: 'First seen', weight: 1.3 }, { key: 'last_seen', label: 'Last seen', weight: 1.3 }],
        rows: aggs.rule_distribution.buckets.map((bucket) => ({
          rule_id: bucket.key, description: bucket.description.buckets[0]?.key || '', level: bucket.level.value,
          groups: bucket.groups.buckets.map((group) => group.key).join(', '), agents: bucket.agents.value, count: bucket.doc_count,
          first_seen: bucket.first_seen.value_as_string, last_seen: bucket.last_seen.value_as_string,
        })) });
    } else if (section === 'attacking_ips' && aggs.attacking_ips) {
      document.sections.push({ title: 'Top attacking source IPs', primary: true,
        columns: [{ key: 'rank', label: '#', weight: 0.3 }, { key: 'ip', label: 'Source IP', weight: 1.1 }, { key: 'count', label: 'Alerts', weight: 0.6 }, { key: 'max_level', label: 'Max level', weight: 0.6 }, { key: 'agents', label: 'Agents targeted', weight: 0.7 }, { key: 'rules', label: 'Rules', weight: 0.5 }, { key: 'top_rule', label: 'Most frequent rule', weight: 2.6 }, { key: 'first_seen', label: 'First seen', weight: 1.3 }, { key: 'last_seen', label: 'Last seen', weight: 1.3 }],
        rows: aggs.attacking_ips.buckets.map((bucket, index) => ({
          rank: index + 1, ip: bucket.key, count: bucket.doc_count, max_level: bucket.max_level.value, agents: bucket.agents.value,
          rules: bucket.rules.value, top_rule: bucket.top_rule.buckets[0]?.key || '', first_seen: bucket.first_seen.value_as_string, last_seen: bucket.last_seen.value_as_string,
        })) });
    } else if (section === 'agent_status') {
      await appendAgentStatus(document);
    }
  }

  if (type.details) {
    const columns = selectedColumns(type, document.columnKeys);
    const rows = [];
    for await (const batch of scrollEvents({ range, ...filters, extra: type.extraQuery, limit: config.reports.maxRows })) {
      for (const event of batch) rows.push(Object.fromEntries(columns.map((column) => [column.key, columnValue(column, event)])));
    }
    document.details = { title: 'Alert details', columns, rows, total, truncated: total > rows.length };
  }
}

async function appendAgentStatus(document) {
  try {
    const summary = await getAgentSummary();
    document.sections.push({ title: 'Agent connectivity', chart: 'bar', labelKey: 'status', valueKey: 'count',
      columns: [{ key: 'status', label: 'Status', weight: 1 }, { key: 'count', label: 'Agents', weight: 1 }],
      rows: [
        { status: 'Active', count: summary.active }, { status: 'Disconnected', count: summary.disconnected },
        { status: 'Never connected', count: summary.never_connected }, { status: 'Pending', count: summary.pending },
      ] });
    return summary;
  } catch (error) {
    // Executive summaries remain useful without Wazuh; record the gap instead of failing.
    document.notes.push(`Agent status unavailable: ${error.message}`);
    return null;
  }
}

async function buildAgentSections(type, document) {
  const summary = await getAgentSummary();
  document.kpis.push(
    { label: 'Total agents', value: summary.total },
    { label: 'Active', value: summary.active, tone: 'low' },
    { label: 'Disconnected', value: summary.disconnected, tone: 'high' },
    { label: 'Never connected', value: summary.never_connected, tone: 'medium' },
    { label: 'Pending', value: summary.pending },
  );
  document.sections.push({ title: 'Agent connectivity', chart: 'bar', labelKey: 'status', valueKey: 'count',
    columns: [{ key: 'status', label: 'Status', weight: 1 }, { key: 'count', label: 'Agents', weight: 1 }],
    rows: [
      { status: 'Active', count: summary.active }, { status: 'Disconnected', count: summary.disconnected },
      { status: 'Never connected', count: summary.never_connected }, { status: 'Pending', count: summary.pending },
    ] });
  if (type.sections.includes('agent_platforms') && summary.platforms.length) {
    document.sections.push({ title: 'Operating system platforms', chart: 'bar', labelKey: 'platform', valueKey: 'count',
      columns: [{ key: 'platform', label: 'Platform', weight: 1 }, { key: 'count', label: 'Agents', weight: 1 }],
      rows: summary.platforms.map((item) => ({ platform: item.key, count: item.doc_count })) });
  }

  const statusOrder = { disconnected: 0, never_connected: 1, pending: 2, active: 3 };
  const filters = document.filters;
  let agents = await getAllAgents({
    q: 'id!=000', // exclude the manager itself, matching /agents/summary/status counts
    ...(filters.status?.length ? { status: filters.status.join(',') } : {}),
    ...(filters.group ? { group: filters.group } : {}),
  });
  const agentFilter = (filters.agent || []).map((value) => String(value).toLowerCase());
  if (agentFilter.length) agents = agents.filter((agent) => agentFilter.some((value) => agent.id === value || String(agent.name).toLowerCase().includes(value)));
  if (type.sortAgents) agents.sort((a, b) => (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9) || String(a.id).localeCompare(String(b.id)));
  const columns = selectedColumns(type, document.columnKeys);
  const rows = agents.slice(0, config.reports.maxRows).map((agent) => Object.fromEntries(columns.map((column) => [column.key, columnValue(column, agent)])));
  document.details = { title: 'Agents', columns, rows, total: agents.length, truncated: agents.length > rows.length };
}

/**
 * Collect report data into a renderer-neutral document.
 * params: { name, reportType, range: {gte,lte,from,to}, filters, columns, generatedBy, timezone }
 */
export async function buildReportDocument({ name, reportType, range, filters = {}, columns = [], generatedBy, timezone = 'UTC' }) {
  const type = REPORT_TYPES[reportType];
  if (!type) throw Object.assign(new Error(`Unknown report type: ${reportType}`), { status: 422 });
  const merged = effectiveFilters(type, filters);
  const document = {
    title: name || type.label,
    reportType,
    reportLabel: type.label,
    period: type.periodless ? null : { from: range.from, to: range.to },
    generatedAt: new Date(),
    generatedBy: generatedBy || 'system',
    timezone,
    filters: merged,
    columnKeys: columns,
    kpis: [],
    sections: [],
    details: null,
    notes: [],
  };

  if (type.source === 'agents') await buildAgentSections(type, document);
  else await buildAlertSections(type, range, merged, document);

  if (document.details?.truncated) {
    document.notes.push(`Detail rows limited to ${document.details.rows.length.toLocaleString('en-US')} of ${document.details.total.toLocaleString('en-US')} matching records (REPORT_MAX_ROWS).`);
  }
  return document;
}
