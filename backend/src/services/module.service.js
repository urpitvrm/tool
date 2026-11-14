import ExcelJS from 'exceljs';
import { config } from '../config/index.js';
import { opensearch, wazuh } from './integration.service.js';
import { getAllAgents } from './siem.service.js';
import { MODULES } from '../constants/modules.js';
import { SEVERITY_LEVELS } from '../constants/severity.js';
import { histogramInterval, parseTimeRange } from '../utils/time-range.js';
import { csvCell } from '../utils/csv.js';

const MAX_RESULT_WINDOW = 10_000;
const httpError = (status, message) => Object.assign(new Error(message), { status });
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];
const SEVERITY_LABELS = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const severityRanges = SEVERITY_ORDER.map((key) => ({ key, from: SEVERITY_LEVELS[key].gte, ...(SEVERITY_LEVELS[key].lte != null ? { to: SEVERITY_LEVELS[key].lte + 1 } : {}) }));

export function getModule(key) {
  const module = MODULES[key];
  if (!module) throw httpError(404, `Unknown module: ${key}`);
  return module;
}

const getPath = (record, path) => {
  if (record == null) return undefined;
  if (Object.prototype.hasOwnProperty.call(record, path)) return record[path];
  return path.split('.').reduce((value, part) => (value == null ? undefined : value[part]), record);
};
const listValues = (raw) => (Array.isArray(raw) ? raw : raw == null || raw === '' ? [] : String(raw).split(','))
  .map((value) => String(value).trim()).filter(Boolean);

// ---------------------------------------------------------------------------------------------------
// Filter parsing: one parser for KPIs, charts, the table and exports.
// ---------------------------------------------------------------------------------------------------

function filterValues(module, query) {
  const values = {};
  for (const filter of module.filters) {
    if (filter.type === 'levelRange') {
      const min = query[`${filter.key}_min`];
      const max = query[`${filter.key}_max`];
      const parse = (value) => {
        if (value == null || value === '') return undefined;
        const number = Number(value);
        if (!Number.isInteger(number) || number < filter.min || number > filter.max) throw httpError(422, `${filter.label} must be between ${filter.min} and ${filter.max}`);
        return number;
      };
      const range = { min: parse(min), max: parse(max) };
      if (range.min != null && range.max != null && range.min > range.max) throw httpError(422, `${filter.label}: minimum is greater than maximum`);
      if (range.min != null || range.max != null) values[filter.key] = range;
      continue;
    }
    const list = listValues(query[filter.key]).slice(0, 50);
    if (!list.length) continue;
    for (const value of list) {
      if (value.length > 200) throw httpError(422, `${filter.label}: value too long`);
      if (filter.pattern && !new RegExp(filter.pattern).test(value)) throw httpError(422, `${filter.label}: invalid value "${value.slice(0, 40)}"`);
    }
    if (filter.type === 'multi') {
      const allowed = new Set(filter.options.map((option) => option.key));
      const invalid = list.filter((value) => !allowed.has(value));
      if (invalid.length) throw httpError(422, `${filter.label}: unknown value "${invalid[0]}"`);
    }
    values[filter.key] = filter.type === 'contains' ? [list.join(',')] : list;
  }
  return values;
}

function fieldValueClause(fields, values) {
  const should = [];
  for (const fieldName of fields) {
    const exact = values.filter((value) => !value.includes('*'));
    if (exact.length) should.push({ terms: { [fieldName]: exact } });
    for (const pattern of values.filter((value) => value.includes('*'))) should.push({ wildcard: { [fieldName]: { value: pattern, case_insensitive: true } } });
  }
  return should.length === 1 ? should[0] : { bool: { should, minimum_should_match: 1 } };
}

function openSearchClause(filter, value) {
  if (filter.type === 'levelRange') return { range: { [filter.field]: { ...(value.min != null ? { gte: value.min } : {}), ...(value.max != null ? { lte: value.max } : {}) } } };
  if (filter.type === 'contains') return { wildcard: { [filter.field]: { value: `*${value[0]}*`, case_insensitive: true } } };
  if (filter.type === 'multi') {
    const should = value.map((key) => {
      const option = filter.options.find((item) => item.key === key);
      if (option.range) return { range: { [filter.field]: option.range } };
      if (option.terms) return { terms: { [filter.field]: option.terms } };
      return { term: { [filter.field]: key } };
    });
    return should.length === 1 ? should[0] : { bool: { should, minimum_should_match: 1 } };
  }
  return fieldValueClause(filter.fields || [filter.field], value);
}

/**
 * Parse request parameters into a module query.
 * Returns { range, q, mode, values, query } where `query` is the OpenSearch bool query (OpenSearch modules).
 */
export function parseModuleQuery(module, query = {}) {
  const q = String(query.q || '').trim();
  if (q.length > 1000) throw httpError(422, 'Search query is too long (max 1000 characters)');
  const mode = query.mode === 'advanced' ? 'advanced' : 'simple';
  const values = filterValues(module, query);
  const range = parseTimeRange({ from: query.from, to: query.to, minutes: query.minutes, hours: query.hours });
  const result = { range, q, mode, values };
  if (module.source !== 'opensearch') return result;

  const filter = [
    { range: { '@timestamp': { gte: range.gte, lte: range.lte, format: 'strict_date_optional_time' } } },
    ...(module.baseQuery || []),
    ...module.filters.filter((item) => values[item.key]).map((item) => openSearchClause(item, values[item.key])),
  ];
  const must = q ? [mode === 'advanced'
    ? { query_string: { query: q, default_operator: 'AND', lenient: true, allow_leading_wildcard: false, analyze_wildcard: true } }
    : { simple_query_string: { query: q, default_operator: 'and', lenient: true } }] : [];
  result.query = { bool: { filter, ...(must.length ? { must } : {}) } };
  return result;
}

// ---------------------------------------------------------------------------------------------------
// OpenSearch aggregations
// ---------------------------------------------------------------------------------------------------

function aggregationFor(agg, range) {
  const histogram = { field: '@timestamp', fixed_interval: histogramInterval(range), min_doc_count: 0, extended_bounds: { min: range.gte, max: range.lte } };
  switch (agg.type) {
    case 'terms': return { terms: { field: agg.field, size: agg.size || 10 } };
    case 'level': return { terms: { field: 'rule.level', size: 16, order: { _key: 'asc' } } };
    case 'severity': return { range: { field: 'rule.level', ranges: severityRanges } };
    case 'timeline': return { date_histogram: histogram };
    case 'severity_timeline': return { date_histogram: histogram, aggs: { severity: { range: { field: 'rule.level', ranges: severityRanges } } } };
    case 'rule': return { terms: { field: 'rule.id', size: 10 }, aggs: { description: { terms: { field: 'rule.description', size: 1 } } } };
    case 'filters': return { filters: { filters: agg.buckets } };
    default: throw new Error(`Unsupported aggregation ${agg.type}`);
  }
}

function normalizeAggregation(agg, raw) {
  switch (agg.type) {
    case 'terms': return { type: 'categorical', buckets: raw.buckets.map((b) => ({ key: String(b.key), label: String(b.key), count: b.doc_count })), other: raw.sum_other_doc_count || 0 };
    case 'level': return { type: 'categorical', buckets: raw.buckets.map((b) => ({ key: String(b.key), label: `Level ${b.key}`, count: b.doc_count })), other: 0 };
    case 'severity': return { type: 'categorical', buckets: raw.buckets.map((b) => ({ key: b.key, label: SEVERITY_LABELS[b.key], count: b.doc_count })), other: 0 };
    case 'rule': return { type: 'categorical', buckets: raw.buckets.map((b) => ({ key: String(b.key), label: `${b.key} · ${b.description.buckets[0]?.key || ''}`.trim(), count: b.doc_count })), other: raw.sum_other_doc_count || 0 };
    case 'filters': return { type: 'categorical', buckets: Object.entries(raw.buckets).map(([key, b]) => ({ key, label: key, count: b.doc_count })), other: 0 };
    case 'timeline': return { type: 'series', series: ['count'], points: raw.buckets.map((b) => ({ time: b.key, count: b.doc_count })) };
    case 'severity_timeline': return {
      type: 'series', series: [...SEVERITY_ORDER].reverse(),
      points: raw.buckets.map((b) => ({ time: b.key, ...Object.fromEntries(b.severity.buckets.map((s) => [s.key, s.doc_count])) })),
    };
    default: return null;
  }
}

function kpiAggregation(kpi) {
  switch (kpi.type) {
    case 'severity': return { filter: { range: { 'rule.level': SEVERITY_LEVELS[kpi.band] } } };
    case 'terms_value': return { filter: { term: { [kpi.field]: kpi.value } } };
    case 'clause': return { filter: kpi.clause };
    case 'cardinality': return { cardinality: { field: kpi.field } };
    default: return null;
  }
}

async function aggregateOpenSearch(module, parsed, charts) {
  const aggs = {};
  for (const kpi of module.kpis) {
    const agg = kpiAggregation(kpi);
    if (agg) aggs[`kpi_${kpi.key}`] = agg;
  }
  for (const item of charts) {
    const agg = aggregationFor(item.agg, parsed.range);
    aggs[`chart_${item.key}`] = item.filter ? { filter: item.filter, aggs: { inner: agg } } : agg;
  }
  const { body } = await opensearch().search({ index: config.eventsIndex, body: { size: 0, track_total_hits: true, query: parsed.query, aggs } });
  const total = body.hits.total?.value || 0;
  const kpis = Object.fromEntries(module.kpis.map((kpi) => {
    if (kpi.type === 'total') return [kpi.key, total];
    const raw = body.aggregations[`kpi_${kpi.key}`];
    return [kpi.key, raw?.value ?? raw?.doc_count ?? 0];
  }));
  const chartData = Object.fromEntries(charts.map((item) => {
    const raw = body.aggregations[`chart_${item.key}`];
    return [item.key, normalizeAggregation(item.agg, item.filter ? raw.inner : raw)];
  }));
  return { total, kpis, charts: chartData };
}

// ---------------------------------------------------------------------------------------------------
// Wazuh agents (filters become one Wazuh query expression shared by list and distinct calls)
// ---------------------------------------------------------------------------------------------------

const WAZUH_VALUE = /^[\w .:@/-]{1,120}$/;

export function agentQueryParams(module, parsed, { includeManager = false } = {}) {
  const conditions = includeManager ? [] : ['id!=000'];
  for (const filter of module.filters) {
    const value = parsed.values[filter.key];
    if (!value) continue;
    for (const item of value) if (!WAZUH_VALUE.test(item.replaceAll('*', ''))) throw httpError(422, `${filter.label}: unsupported characters`);
    if (filter.type === 'contains') conditions.push(`${filter.field}~${value[0]}`);
    else conditions.push(`(${value.map((item) => (item.includes('*') ? `${filter.field}~${item.replaceAll('*', '')}` : `${filter.field}=${item}`)).join(',')})`);
  }
  const params = {};
  if (parsed.q && parsed.mode === 'advanced') {
    if (/[\r\n]/.test(parsed.q)) throw httpError(422, 'Invalid query');
    conditions.push(`(${parsed.q})`); // Wazuh query language, e.g. os.platform=windows;version<4.8
  } else if (parsed.q) {
    params.search = parsed.q;
  }
  if (conditions.length) params.q = conditions.join(';');
  return params;
}

async function agentDistinct(fieldName, params) {
  const { data } = await wazuh('/agents/stats/distinct', { params: { ...params, fields: fieldName, limit: 500 } });
  const counts = new Map();
  for (const item of data?.data?.affected_items || []) {
    const raw = getPath(item, fieldName);
    for (const key of Array.isArray(raw) ? raw : [raw ?? 'unknown']) counts.set(String(key), (counts.get(String(key)) || 0) + item.count);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([key, count]) => ({ key, label: key.replaceAll('_', ' '), count }));
}

async function agentConnectionTrend(range) {
  // Wazuh raises alerts for agent lifecycle changes; these give real historical connection activity.
  const { body } = await opensearch().search({ index: config.eventsIndex, body: {
    size: 0,
    query: { bool: { filter: [{ terms: { 'rule.id': ['501', '502', '503', '504', '505', '506'] } }, { range: { '@timestamp': { gte: range.gte, lte: range.lte } } }] } },
    aggs: { byRule: { terms: { field: 'rule.description', size: 5 }, aggs: { timeline: { date_histogram: { field: '@timestamp', fixed_interval: histogramInterval(range), min_doc_count: 0, extended_bounds: { min: range.gte, max: range.lte } } } } } },
  } });
  const groups = body.aggregations.byRule.buckets;
  const times = groups[0]?.timeline.buckets.map((bucket) => bucket.key) || [];
  return {
    type: 'series', series: groups.map((group) => group.key),
    points: times.map((time, index) => ({ time, ...Object.fromEntries(groups.map((group) => [group.key, group.timeline.buckets[index]?.doc_count || 0])) })),
  };
}

async function aggregateAgents(module, parsed, charts) {
  const params = agentQueryParams(module, parsed);
  const status = await agentDistinct('status', params);
  const total = status.reduce((sum, bucket) => sum + bucket.count, 0);
  const kpis = Object.fromEntries(module.kpis.map((kpi) => [kpi.key, kpi.type === 'total' ? total : status.find((bucket) => bucket.key === kpi.value)?.count || 0]));
  const chartData = {};
  await Promise.all(charts.map(async (item) => {
    try {
      if (item.agg.type === 'distinct') chartData[item.key] = { type: 'categorical', buckets: item.agg.field === 'status' ? status : await agentDistinct(item.agg.field, params), other: 0 };
      else if (item.agg.type === 'connection_trend') chartData[item.key] = await agentConnectionTrend(parsed.range);
    } catch (error) {
      chartData[item.key] = { type: 'error', message: error.message };
    }
  }));
  return { total, kpis, charts: chartData };
}

// ---------------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------------

/** KPIs plus the charts for one tab. `scope` = 'dashboard' | 'search'. */
export async function aggregate(moduleKey, query, scope = 'dashboard') {
  const module = getModule(moduleKey);
  const parsed = parseModuleQuery(module, query);
  const charts = scope === 'search' ? [module.primaryChart, ...(module.searchCharts || [])] : module.dashboardCharts;
  const result = module.source === 'wazuh' ? await aggregateAgents(module, parsed, charts) : await aggregateOpenSearch(module, parsed, charts);
  return { ...result, range: { from: parsed.range.gte, to: parsed.range.lte, interval: histogramInterval(parsed.range) } };
}

// ---- Field discovery (columns can include any mapped field) --------------------------------------

const SORTABLE_TYPES = new Set(['keyword', 'constant_keyword', 'ip', 'long', 'integer', 'short', 'byte', 'double', 'float', 'half_float', 'scaled_float', 'date', 'boolean']);
let fieldCache = { at: 0, fields: null };

async function indexFields() {
  if (fieldCache.fields && Date.now() - fieldCache.at < 10 * 60_000) return fieldCache.fields;
  const { body } = await opensearch().indices.getMapping({ index: config.eventsIndex });
  const fields = new Map();
  const walk = (properties, prefix) => {
    for (const [name, definition] of Object.entries(properties || {})) {
      const path = prefix ? `${prefix}.${name}` : name;
      if (definition.properties) walk(definition.properties, path);
      else if (definition.type && !fields.has(path)) fields.set(path, definition.type);
    }
  };
  for (const index of Object.values(body)) walk(index.mappings?.properties, '');
  fieldCache = { at: Date.now(), fields };
  return fields;
}

export async function moduleFields(moduleKey) {
  const module = getModule(moduleKey);
  const catalog = module.fields.map((item) => ({ ...item, catalog: true }));
  if (module.source !== 'opensearch') return catalog;
  const known = new Set(catalog.map((item) => item.key));
  const discovered = [...(await indexFields()).entries()]
    .filter(([key]) => !known.has(key))
    .sort(([a], [b]) => a.localeCompare(b))
    .slice(0, 2000)
    .map(([key, type]) => ({ key, label: key, discovered: true, type: type === 'text' ? 'text' : SORTABLE_TYPES.has(type) ? (type === 'date' ? 'date' : /long|integer|short|byte|double|float/.test(type) ? 'number' : 'keyword') : type, sortable: SORTABLE_TYPES.has(type) }));
  return [...catalog, ...discovered];
}

async function resolveSort(module, sort, order) {
  const direction = order === 'asc' ? 'asc' : 'desc';
  const fallback = module.defaultSort;
  if (!sort) return { field: fallback.field, order: order ? direction : fallback.order };
  const catalogField = module.fields.find((item) => item.key === sort);
  if (catalogField) {
    if (!catalogField.sortable) throw httpError(422, `${catalogField.label} cannot be sorted`);
    return { field: sort, order: direction };
  }
  if (module.source === 'opensearch') {
    const type = (await indexFields()).get(sort);
    if (type && SORTABLE_TYPES.has(type)) return { field: sort, order: direction };
  }
  throw httpError(422, `Sorting by "${String(sort).slice(0, 60)}" is not supported`);
}

/** Paged records matching exactly the same filters as `aggregate`. */
export async function records(moduleKey, query) {
  const module = getModule(moduleKey);
  const parsed = parseModuleQuery(module, query);
  const page = Math.max(1, Number(query.page) || 1);
  const size = Math.min(200, Math.max(1, Number(query.size) || 25));
  const sort = await resolveSort(module, query.sort, query.order);

  if (module.source === 'wazuh') {
    const params = agentQueryParams(module, parsed);
    const { data } = await wazuh('/agents', { params: { ...params, limit: size, offset: (page - 1) * size, sort: `${sort.order === 'desc' ? '-' : '+'}${sort.field}` } });
    return { total: data?.data?.total_affected_items || 0, page, size, sort, items: data?.data?.affected_items || [] };
  }

  if ((page - 1) * size + size > MAX_RESULT_WINDOW) throw httpError(422, `Only the first ${MAX_RESULT_WINDOW.toLocaleString('en-US')} results can be paged. Narrow the filters or change the sort.`);
  const { body } = await opensearch().search({ index: config.eventsIndex, body: {
    from: (page - 1) * size, size, track_total_hits: true, query: parsed.query,
    sort: [{ [sort.field]: { order: sort.order, unmapped_type: 'keyword' } }, ...(sort.field !== '@timestamp' ? [{ '@timestamp': { order: 'desc' } }] : [])],
  } });
  return {
    total: body.hits.total?.value || 0, page, size, sort, max_window: MAX_RESULT_WINDOW,
    items: body.hits.hits.map((hit) => ({ ...hit._source, _id: hit._id, _index: hit._index })),
  };
}

/** Top values for a filter field (filter suggestions), within the current time range. */
export async function fieldValues(moduleKey, query) {
  const module = getModule(moduleKey);
  const filter = module.filters.find((item) => item.suggest === query.field);
  if (!filter) throw httpError(422, 'Suggestions are not available for this field');
  if (module.source === 'wazuh') return (await agentDistinct(filter.suggest, agentQueryParams(module, parseModuleQuery(module, {})))).slice(0, 30);
  const parsed = parseModuleQuery(module, { from: query.from, to: query.to, minutes: query.minutes });
  const { body } = await opensearch().search({ index: config.eventsIndex, body: { size: 0, query: parsed.query, aggs: { values: { terms: { field: filter.suggest, size: 30 } } } } });
  return body.aggregations.values.buckets.map((bucket) => ({ key: String(bucket.key), count: bucket.doc_count }));
}

// ---- Export -------------------------------------------------------------------------------------

async function exportColumns(module, requested) {
  const available = new Map((await moduleFields(module.key)).map((item) => [item.key, item]));
  const keys = listValues(requested).filter((key) => available.has(key)).slice(0, 80);
  return (keys.length ? keys : module.defaultColumns).map((key) => available.get(key) || { key, label: key });
}

const cellText = (value) => (Array.isArray(value) ? value.join(', ') : value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : value);

/** Iterate every matching record in batches (scroll for OpenSearch, paging for Wazuh). */
async function* allRecords(module, parsed, sort, limit) {
  if (module.source === 'wazuh') {
    const agents = await getAllAgents({ ...agentQueryParams(module, parsed), sort: `${sort.order === 'desc' ? '-' : '+'}${sort.field}` });
    yield agents.slice(0, limit);
    return;
  }
  const client = opensearch();
  let scrollId;
  let emitted = 0;
  try {
    let response = await client.search({ index: config.eventsIndex, scroll: '1m', body: { size: 1000, query: parsed.query, sort: [{ [sort.field]: { order: sort.order, unmapped_type: 'keyword' } }] } });
    scrollId = response.body._scroll_id;
    while (response.body.hits.hits.length && emitted < limit) {
      const batch = response.body.hits.hits.slice(0, limit - emitted).map((hit) => hit._source);
      emitted += batch.length;
      yield batch;
      if (emitted >= limit) break;
      response = await client.scroll({ scroll_id: scrollId, scroll: '1m' });
      scrollId = response.body._scroll_id || scrollId;
    }
  } finally {
    if (scrollId) await client.clearScroll({ scroll_id: scrollId }).catch(() => {});
  }
}

/** Stream CSV (unbounded) or build XLSX (capped at REPORT_MAX_ROWS) for the current filters. */
export async function exportRecords(moduleKey, query, res) {
  const module = getModule(moduleKey);
  const parsed = parseModuleQuery(module, query);
  const sort = await resolveSort(module, query.sort, query.order);
  const columns = await exportColumns(module, query.columns);
  const format = query.format === 'xlsx' ? 'xlsx' : 'csv';
  const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '');
  const fileName = `${module.key}_${stamp}.${format}`;
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);

  if (format === 'xlsx') {
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet(module.label.slice(0, 31), { views: [{ state: 'frozen', ySplit: 1 }] });
    sheet.columns = columns.map((column) => ({ header: column.label, key: column.key, width: Math.min(60, Math.max(12, column.label.length + 4)) }));
    for await (const batch of allRecords(module, parsed, sort, config.reports.maxRows)) {
      for (const record of batch) sheet.addRow(Object.fromEntries(columns.map((column) => [column.key, cellText(getPath(record, column.key))])));
    }
    sheet.getRow(1).font = { bold: true };
    sheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: 1, column: columns.length } };
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.end(Buffer.from(await workbook.xlsx.writeBuffer()));
    return;
  }

  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.write(`﻿${columns.map((column) => csvCell(column.label)).join(',')}\r\n`);
  for await (const batch of allRecords(module, parsed, sort, Infinity)) {
    if (res.destroyed) break;
    const chunk = batch.map((record) => columns.map((column) => csvCell(cellText(getPath(record, column.key)))).join(',')).join('\r\n');
    if (!res.write(`${chunk}\r\n`)) await new Promise((resolve) => { res.once('drain', resolve); res.once('close', resolve); });
  }
  res.end();
}
