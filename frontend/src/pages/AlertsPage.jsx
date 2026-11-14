import React, { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, keepPreviousData } from '@tanstack/react-query';
import { Copy, FileBarChart, Filter, RefreshCw, RotateCcw, Search } from 'lucide-react';
import { api } from '../api.js';
import { ChipToggle, Drawer, Empty, ErrorState, Field, Loading, PageHeading, Pagination, Segmented, SeverityBadge, SortHeader, TimeRangePicker, useToast } from '../components/common.jsx';
import { downloadFile, fmtDate, SEVERITIES, splitList } from '../lib/format.js';
import { rangeParams } from '../lib/time.js';

const EMPTY_FILTERS = { q: '', severity: [], agent: '', rule_id: '', srcip: '', dstip: '' };
const FILTER_KEYS = Object.keys(EMPTY_FILTERS);

function filtersFromUrl(params) {
  const filters = { ...EMPTY_FILTERS };
  for (const key of FILTER_KEYS) {
    const value = params.get(key);
    if (value) filters[key] = key === 'severity' ? value.split(',') : value;
  }
  return filters;
}

/** Normalize the filter form into API query parameters (comma-separated lists). */
export function alertQueryParams(filters) {
  const params = {};
  if (filters.q.trim()) params.q = filters.q.trim();
  if (filters.severity.length) params.severity = filters.severity.join(',');
  for (const key of ['agent', 'rule_id', 'srcip', 'dstip']) {
    const values = splitList(filters[key]);
    if (values.length) params[key] = values.join(',');
  }
  return params;
}

const COLUMNS = [
  ['Timestamp', '@timestamp'], ['Level', 'rule.level'], ['Rule', 'rule.id'], ['Description'], ['Agent', 'agent.name'], ['Source IP'], ['Destination IP'],
];

export default function AlertsPage({ range: initialRange }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [range, setRange] = useState(initialRange);
  const [draft, setDraft] = useState(() => filtersFromUrl(searchParams));
  const [filters, setFilters] = useState(draft);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(50);
  const [sort, setSort] = useState({ field: '@timestamp', order: 'desc' });
  const [selected, setSelected] = useState(null);
  const [exporting, setExporting] = useState(false);
  const { notify } = useToast();

  const params = useMemo(() => ({ ...rangeParams(range), ...alertQueryParams(filters), page, size, sort: sort.field, order: sort.order }), [range, filters, page, size, sort]);
  const query = useQuery({
    queryKey: ['alerts', params],
    queryFn: () => api.get('/events', { params }).then((response) => response.data),
    placeholderData: keepPreviousData,
  });

  function apply(next = draft) {
    setFilters(next);
    setPage(1);
    const urlParams = {};
    for (const [key, value] of Object.entries(alertQueryParams(next))) urlParams[key] = value;
    setSearchParams(urlParams, { replace: true });
  }

  function quickFilter(key, value) {
    const next = { ...EMPTY_FILTERS, [key]: String(value) };
    setDraft(next);
    apply(next);
    setSelected(null);
  }

  async function exportCsv() {
    setExporting(true);
    try {
      const { page: _p, size: _s, ...exportParams } = params;
      await downloadFile('/events/export', 'security_alerts.csv', exportParams);
    } catch (error) {
      notify(error.message, 'error');
    } finally {
      setExporting(false);
    }
  }

  const rows = query.data?.items || [];
  const activeFilters = Object.keys(alertQueryParams(filters)).length;

  return (
    <>
      <PageHeading title="Alerts" description="Wazuh security alerts from OpenSearch. Filter by severity, agent, rule and network attributes.">
        <TimeRangePicker value={range} onChange={(next) => { setRange(next); setPage(1); }} />
        <button className="secondary" onClick={() => query.refetch()}><RefreshCw size={14} /> Refresh</button>
        <button className="secondary" disabled={exporting} onClick={exportCsv}><FileBarChart size={14} /> {exporting ? 'Exporting…' : 'Export CSV'}</button>
      </PageHeading>

      <form className="panel filter-panel" onSubmit={(event) => { event.preventDefault(); apply(); }}>
        <div className="filter-grid">
          <Field label="Search" className="span-2">
            <div className="query-input"><Search size={14} /><input value={draft.q} onChange={(event) => setDraft({ ...draft, q: event.target.value })} placeholder="Text, field:value, wildcards, AND/OR…" /></div>
          </Field>
          <Field label="Severity" className="span-2">
            <ChipToggle options={SEVERITIES.map((item) => ({ key: item.key, label: `${item.label} · ${item.levels}` }))} value={draft.severity} onChange={(severity) => setDraft({ ...draft, severity })} />
          </Field>
          <Field label="Agent" hint="Name, ID or wildcard (web-*)"><input value={draft.agent} onChange={(event) => setDraft({ ...draft, agent: event.target.value })} placeholder="e.g. 001, web-*" /></Field>
          <Field label="Rule ID"><input value={draft.rule_id} onChange={(event) => setDraft({ ...draft, rule_id: event.target.value })} placeholder="e.g. 5710, 5712" inputMode="numeric" /></Field>
          <Field label="Source IP"><input value={draft.srcip} onChange={(event) => setDraft({ ...draft, srcip: event.target.value })} placeholder="e.g. 10.0.0.5 or 10.0.*" /></Field>
          <Field label="Destination IP"><input value={draft.dstip} onChange={(event) => setDraft({ ...draft, dstip: event.target.value })} placeholder="e.g. 192.168.1.10" /></Field>
        </div>
        <div className="filter-actions">
          <span className="muted"><Filter size={12} /> {activeFilters ? `${activeFilters} filter${activeFilters > 1 ? 's' : ''} applied` : 'No filters applied'}</span>
          <button type="button" className="secondary" onClick={() => { setDraft(EMPTY_FILTERS); apply(EMPTY_FILTERS); }}><RotateCcw size={13} /> Reset</button>
          <button className="primary"><Search size={14} /> Apply filters</button>
        </div>
      </form>

      <div className="results-head">
        <div><h3>Alert results</h3><span>{(query.data?.total || 0).toLocaleString()} alerts {query.isFetching && !query.isLoading ? '· updating…' : ''}</span></div>
      </div>
      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr>{COLUMNS.map(([label, field]) => <SortHeader key={label} label={label} field={field} sort={sort} onSort={(next) => { setSort(next); setPage(1); }} />)}</tr></thead>
            <tbody>
              {query.isLoading ? <tr><td colSpan={COLUMNS.length}><Loading /></td></tr>
                : query.error ? <tr><td colSpan={COLUMNS.length}><ErrorState error={query.error} /></td></tr>
                  : rows.length ? rows.map((row) => (
                    <tr key={row._id} className="click-row" onClick={() => setSelected(row)}>
                      <td className="timestamp">{fmtDate(row['@timestamp'])}</td>
                      <td><SeverityBadge level={row.rule?.level} /></td>
                      <td><code>{row.rule?.id ?? '—'}</code></td>
                      <td className="event-desc">{row.rule?.description || '—'}</td>
                      <td>{row.agent?.name || '—'}<small className="cell-sub">{row.agent?.id}</small></td>
                      <td className="mono">{row.data?.srcip || '—'}</td>
                      <td className="mono">{row.data?.dstip || '—'}</td>
                    </tr>
                  )) : <tr><td colSpan={COLUMNS.length}><Empty message="No alerts match the selected time range and filters." /></td></tr>}
            </tbody>
          </table>
        </div>
        <Pagination page={page} size={size} total={query.data?.total || 0} maxWindow={query.data?.max_window} onPage={setPage} onSize={(value) => { setSize(value); setPage(1); }} />
      </div>
      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} onFilter={quickFilter} />}
    </>
  );
}

function DetailRow({ label, value, mono, onFilter }) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return null;
  const text = Array.isArray(value) ? value.join(', ') : String(value);
  return (
    <div className="detail-row">
      <span>{label}</span>
      <b className={mono ? 'mono' : ''}>{text}</b>
      {onFilter && <button className="text-button" onClick={onFilter} title={`Filter by ${label}`}>filter</button>}
    </div>
  );
}

export function AlertDrawer({ alert, onClose, onFilter }) {
  const [tab, setTab] = useState('summary');
  const { notify } = useToast();
  const rule = alert.rule || {};
  const data = alert.data || {};
  const filterBy = (key, value) => onFilter && value != null && value !== '' ? () => onFilter(key, value) : undefined;
  return (
    <Drawer
      title={rule.description || 'Security alert'}
      eyebrow="ALERT DETAILS"
      onClose={onClose}
      actions={<button className="secondary wide" onClick={() => navigator.clipboard?.writeText(JSON.stringify(alert, null, 2)).then(() => notify('Alert JSON copied'))}><Copy size={13} /> Copy raw JSON</button>}
    >
      <div className="drawer-meta"><SeverityBadge level={rule.level} /><code>{alert._id}</code></div>
      <Segmented options={[{ key: 'summary', label: 'Summary' }, { key: 'json', label: 'Raw JSON' }]} value={tab} onChange={setTab} />
      {tab === 'json' ? <pre className="json-view">{JSON.stringify(alert, null, 2)}</pre> : (
        <div className="detail-sections">
          <section><h4>Event</h4>
            <DetailRow label="Timestamp" value={fmtDate(alert['@timestamp'])} />
            <DetailRow label="Location" value={alert.location} mono />
            <DetailRow label="Decoder" value={alert.decoder?.name} />
            <DetailRow label="Manager" value={alert.manager?.name} />
          </section>
          <section><h4>Rule</h4>
            <DetailRow label="Rule ID" value={rule.id} mono onFilter={filterBy('rule_id', rule.id)} />
            <DetailRow label="Level" value={rule.level} />
            <DetailRow label="Description" value={rule.description} />
            <DetailRow label="Groups" value={rule.groups} />
            <DetailRow label="Fired times" value={rule.firedtimes} />
            <DetailRow label="MITRE technique" value={rule.mitre?.id} />
            <DetailRow label="MITRE tactic" value={rule.mitre?.tactic} />
            <DetailRow label="PCI DSS" value={rule.pci_dss} />
            <DetailRow label="GDPR" value={rule.gdpr} />
          </section>
          <section><h4>Agent</h4>
            <DetailRow label="Name" value={alert.agent?.name} onFilter={filterBy('agent', alert.agent?.name)} />
            <DetailRow label="ID" value={alert.agent?.id} mono />
            <DetailRow label="IP" value={alert.agent?.ip} mono />
          </section>
          {(data.srcip || data.dstip || data.srcuser || data.dstuser) && (
            <section><h4>Network &amp; identity</h4>
              <DetailRow label="Source IP" value={data.srcip} mono onFilter={filterBy('srcip', data.srcip)} />
              <DetailRow label="Source port" value={data.srcport} mono />
              <DetailRow label="Destination IP" value={data.dstip} mono onFilter={filterBy('dstip', data.dstip)} />
              <DetailRow label="Destination port" value={data.dstport} mono />
              <DetailRow label="Source user" value={data.srcuser} />
              <DetailRow label="Destination user" value={data.dstuser} />
            </section>
          )}
          {alert.full_log && <section><h4>Full log</h4><pre className="json-view compact">{alert.full_log}</pre></section>}
        </div>
      )}
    </Drawer>
  );
}
