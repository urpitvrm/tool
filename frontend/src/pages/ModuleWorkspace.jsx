import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import { BarChart3, Bookmark, FileBarChart, Filter, LayoutDashboard, RefreshCw, RotateCcw, Save, Search, SlidersHorizontal, Trash2 } from 'lucide-react';
import { api, apiError } from '../api.js';
import { ChipToggle, ErrorState, Field, Loading, PageHeading, TimeRangePicker, useToast } from '../components/common.jsx';
import { ChartCard, KpiRow } from '../components/charts.jsx';
import DataTable from '../components/DataTable.jsx';
import { AgentDrawer, AlertDrawer } from '../components/RecordDrawers.jsx';
import { downloadFile, fmtNumber, splitList } from '../lib/format.js';
import { rangeLabel, rangeParams } from '../lib/time.js';

const REFRESH = [[0, 'Off'], [30, '30 s'], [60, '1 min'], [300, '5 min']];
const SEVERITY_BANDS = { critical: [15, 15], high: [12, 14], medium: [7, 11], low: [0, 6] };

export function useModules() {
  return useQuery({ queryKey: ['modules'], queryFn: () => api.get('/modules').then((r) => r.data), staleTime: 600_000 });
}

// ---- Shared filter state <-> query parameters -------------------------------------------------

export function emptyFilterForm(module) {
  return Object.fromEntries(module.filters.map((filter) => [filter.key, filter.type === 'multi' ? [] : filter.type === 'levelRange' ? { min: '', max: '' } : '']));
}

export function filterParams(module, form) {
  const params = {};
  for (const filter of module.filters) {
    const value = form[filter.key];
    if (filter.type === 'levelRange') {
      if (value?.min !== '' && value?.min != null) params[`${filter.key}_min`] = value.min;
      if (value?.max !== '' && value?.max != null) params[`${filter.key}_max`] = value.max;
    } else if (filter.type === 'multi') {
      if (value?.length) params[filter.key] = value.join(',');
    } else if (filter.type === 'contains') {
      if (String(value || '').trim()) params[filter.key] = String(value).trim();
    } else {
      const list = splitList(value);
      if (list.length) params[filter.key] = list.join(',');
    }
  }
  return params;
}

function formFromParams(module, params) {
  const form = emptyFilterForm(module);
  for (const filter of module.filters) {
    if (filter.type === 'levelRange') form[filter.key] = { min: params.get(`${filter.key}_min`) ?? '', max: params.get(`${filter.key}_max`) ?? '' };
    else if (filter.type === 'multi') form[filter.key] = (params.get(filter.key) || '').split(',').filter(Boolean);
    else form[filter.key] = (params.get(filter.key) || '').split(',').join(', ');
  }
  return form;
}

/** Map a clicked chart bucket to a Search-tab filter of the same module. */
function drillFilter(module, chart, bucket) {
  const levelFilter = module.filters.find((filter) => filter.type === 'levelRange');
  if (chart.aggType === 'level' && levelFilter) return { [levelFilter.key]: { min: bucket.key, max: bucket.key } };
  if (chart.aggType === 'severity') {
    if (module.filters.some((filter) => filter.key === 'severity')) return { severity: [bucket.key] };
    if (levelFilter) return { [levelFilter.key]: { min: SEVERITY_BANDS[bucket.key][0], max: SEVERITY_BANDS[bucket.key][1] } };
  }
  if (chart.aggType === 'rule') return module.filters.some((filter) => filter.key === 'rule_id') ? { rule_id: bucket.key } : null;
  if (chart.aggType === 'filters') {
    const filter = module.filters.find((item) => item.type === 'multi' && item.options.some((option) => option.label === bucket.key));
    return filter ? { [filter.key]: [filter.options.find((option) => option.label === bucket.key).key] } : null;
  }
  const filter = module.filters.find((item) => item.field === chart.aggField);
  if (!filter) return null;
  if (filter.type === 'multi') return filter.options.some((option) => option.key === bucket.key) ? { [filter.key]: [bucket.key] } : null;
  return { [filter.key]: bucket.key };
}

function countActive(module, form) {
  const params = filterParams(module, form);
  return module.filters.filter((filter) => filter.key in params || `${filter.key}_min` in params || `${filter.key}_max` in params).length;
}

// ---- Page ------------------------------------------------------------------------------------------

export default function ModuleWorkspace({ moduleKey, range: globalRange }) {
  const modules = useModules();
  const [searchParams, setSearchParams] = useSearchParams();
  const module = modules.data?.find((item) => item.key === moduleKey);
  const tab = searchParams.get('tab') === 'search' ? 'search' : 'dashboard';
  const [range, setRange] = useState(globalRange);

  if (modules.isLoading) return <Loading />;
  if (modules.error) return <ErrorState error={modules.error} />;
  if (!module) return <ErrorState error="This module is not available for your role." title="Module unavailable" hint="" />;

  const switchTab = (next, extra = {}) => setSearchParams({ tab: next, ...extra });

  return (
    <>
      <PageHeading title={module.label} eyebrow={(module.category || 'Security').toUpperCase()} description={module.description}>
        <TimeRangePicker value={range} onChange={setRange} />
      </PageHeading>
      <div className="module-tabs" role="tablist">
        <button role="tab" aria-selected={tab === 'dashboard'} className={tab === 'dashboard' ? 'on' : ''} onClick={() => switchTab('dashboard')}><LayoutDashboard size={14} /> Dashboard</button>
        <button role="tab" aria-selected={tab === 'search'} className={tab === 'search' ? 'on' : ''} onClick={() => switchTab('search')}><Search size={14} /> Search</button>
        <span className="tab-source">{module.source === 'wazuh' ? 'Source: Wazuh Manager API' : 'Source: OpenSearch'} · {rangeLabel(range)}</span>
      </div>
      {tab === 'dashboard'
        ? <DashboardTab module={module} range={range} onDrill={(filters) => switchTab('search', filters)} />
        : <SearchTab key={module.key} module={module} range={range} searchParams={searchParams} setSearchParams={setSearchParams} />}
    </>
  );
}

function RecordDrawer({ module, record, onClose, onFilter }) {
  const navigate = useNavigate();
  if (!record) return null;
  return module.source === 'wazuh'
    ? <AgentDrawer agent={record} onClose={onClose} onViewAlerts={(agent) => navigate(`/events?tab=search&agent_id=${encodeURIComponent(agent.id)}`)} />
    : <AlertDrawer alert={record} onClose={onClose} onFilter={onFilter} />;
}

// ---- Dashboard tab ---------------------------------------------------------------------------

function DashboardTab({ module, range, onDrill }) {
  const [refresh, setRefresh] = useState(60);
  const [selected, setSelected] = useState(null);
  const params = useMemo(() => rangeParams(range), [range]);
  const aggregations = useQuery({
    queryKey: ['module-aggs', module.key, 'dashboard', params],
    queryFn: () => api.get(`/modules/${module.key}/aggregations`, { params: { ...params, scope: 'dashboard' } }).then((r) => r.data),
    refetchInterval: refresh ? refresh * 1000 : false,
    placeholderData: keepPreviousData,
  });
  const drill = (chart, bucket) => {
    const filters = drillFilter(module, chart, bucket);
    if (!filters) return;
    const form = { ...emptyFilterForm(module), ...filters };
    onDrill(filterParams(module, form));
  };

  return (
    <>
      <div className="tab-toolbar">
        <span className="muted"><BarChart3 size={13} /> Click a chart element to open the matching records in Search.</span>
        <select className="compact-select" value={refresh} onChange={(event) => setRefresh(Number(event.target.value))} aria-label="Auto refresh">
          {REFRESH.map(([seconds, label]) => <option key={seconds} value={seconds}>Auto refresh: {label}</option>)}
        </select>
        <button className="secondary" onClick={() => aggregations.refetch()}><RefreshCw size={14} /> Refresh</button>
      </div>
      <KpiRow kpis={module.kpis} result={aggregations} inventory={module.source === 'wazuh'} />
      <div className="module-chart-grid">
        {module.dashboardCharts.map((chart) => <ChartCard key={chart.key} chart={chart} result={aggregations} onSelect={drill} />)}
      </div>
      {/* Event modules show records only in the Search tab; the agent inventory stays on its dashboard. */}
      {module.source === 'wazuh' && <DataTable module={module} params={params} tableKey="dashboard" title="Agent inventory" onOpen={setSelected} />}
      <RecordDrawer module={module} record={selected} onClose={() => setSelected(null)}
        onFilter={(key, value) => { setSelected(null); const form = { ...emptyFilterForm(module), [key]: key === 'level' ? { min: value, max: value } : String(value) }; onDrill(filterParams(module, form)); }} />
    </>
  );
}

// ---- Search tab ------------------------------------------------------------------------------

function FilterInput({ module, filter, value, onChange, range }) {
  const [suggest, setSuggest] = useState(false);
  const values = useQuery({
    queryKey: ['module-values', module.key, filter.suggest, rangeParams(range)],
    queryFn: () => api.get(`/modules/${module.key}/values`, { params: { field: filter.suggest, ...rangeParams(range) } }).then((r) => r.data),
    enabled: Boolean(filter.suggest && suggest), staleTime: 120_000,
  });
  if (filter.type === 'multi') return <Field label={filter.label} className="span-2"><ChipToggle options={filter.options.map((option) => ({ ...option, tone: option.key }))} value={value} onChange={onChange} /></Field>;
  if (filter.type === 'levelRange') {
    return (
      <Field label={`${filter.label} (${filter.min}–${filter.max})`}>
        <div className="inline-pair">
          <input type="number" min={filter.min} max={filter.max} placeholder="Min" value={value.min} onChange={(event) => onChange({ ...value, min: event.target.value })} aria-label={`${filter.label} minimum`} />
          <input type="number" min={filter.min} max={filter.max} placeholder="Max" value={value.max} onChange={(event) => onChange({ ...value, max: event.target.value })} aria-label={`${filter.label} maximum`} />
        </div>
      </Field>
    );
  }
  const listId = `suggest-${module.key}-${filter.key}`;
  return (
    <Field label={filter.label} hint={filter.type === 'list' ? 'Comma-separated · * wildcard' : 'Contains'}>
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder={filter.placeholder} list={filter.suggest ? listId : undefined} onFocus={() => setSuggest(true)} maxLength={500} />
      {filter.suggest && <datalist id={listId}>{(values.data || []).map((item) => <option key={item.key} value={item.key}>{`${item.label || item.key} (${item.count})`}</option>)}</datalist>}
    </Field>
  );
}

function SearchTab({ module, range, searchParams, setSearchParams }) {
  const { notify } = useToast();
  const client = useQueryClient();
  const [draftQ, setDraftQ] = useState(() => searchParams.get('q') || '');
  const [mode, setMode] = useState(() => (searchParams.get('mode') === 'advanced' ? 'advanced' : 'simple'));
  const [draft, setDraft] = useState(() => formFromParams(module, searchParams));
  const [applied, setApplied] = useState(() => ({ q: searchParams.get('q') || '', mode: searchParams.get('mode') === 'advanced' ? 'advanced' : 'simple', form: formFromParams(module, searchParams) }));
  const [selected, setSelected] = useState(null);
  const [exporting, setExporting] = useState(false);

  // Drill-down links update the URL; adopt their filters.
  const urlKey = searchParams.toString();
  useEffect(() => {
    const form = formFromParams(module, searchParams);
    const q = searchParams.get('q') || '';
    const nextMode = searchParams.get('mode') === 'advanced' ? 'advanced' : 'simple';
    setDraft(form); setDraftQ(q); setMode(nextMode);
    setApplied({ q, mode: nextMode, form });
  }, [urlKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // ONE parameter object drives the count, bar graph, extra charts, table and exports.
  const params = useMemo(() => ({
    ...rangeParams(range),
    ...(applied.q ? { q: applied.q, mode: applied.mode } : {}),
    ...filterParams(module, applied.form),
  }), [range, applied, module]);

  const aggregations = useQuery({
    queryKey: ['module-aggs', module.key, 'search', params],
    queryFn: () => api.get(`/modules/${module.key}/aggregations`, { params: { ...params, scope: 'search' } }).then((r) => r.data),
    placeholderData: keepPreviousData,
  });
  const preference = useQuery({ queryKey: ['table-pref', module.key, 'search'], queryFn: () => api.get(`/modules/${module.key}/preferences/search`).then((r) => r.data), staleTime: Infinity });
  const saved = useQuery({ queryKey: ['saved-searches', module.key], queryFn: () => api.get('/saved-searches', { params: { module: module.key } }).then((r) => r.data) });

  function apply(next = { q: draftQ.trim(), mode, form: draft }) {
    const urlParams = { tab: 'search', ...filterParams(module, next.form), ...(next.q ? { q: next.q, mode: next.mode } : {}) };
    setSearchParams(urlParams);
    setApplied(next);
  }

  function clearAll() {
    const form = emptyFilterForm(module);
    setDraft(form); setDraftQ(''); setMode('simple');
    apply({ q: '', mode: 'simple', form });
  }

  function addFilter(key, value) {
    setSelected(null);
    if (!module.filters.some((filter) => filter.key === key)) return notify('That filter is not available in this module.', 'error');
    const form = { ...applied.form, [key]: key === 'level' ? { min: value, max: value } : String(value) };
    setDraft(form);
    apply({ ...applied, form });
  }

  async function saveSearch() {
    const name = window.prompt('Name this search', applied.q || `${module.label} search`);
    if (!name) return;
    try {
      await api.post('/saved-searches', { module: module.key, name, query: { q: applied.q, mode: applied.mode, filters: applied.form, range } });
      client.invalidateQueries({ queryKey: ['saved-searches', module.key] });
      notify(`Saved search "${name}"`);
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  function loadSearch(id) {
    const entry = (saved.data || []).find((item) => String(item.id) === id);
    if (!entry) return;
    const form = { ...emptyFilterForm(module), ...(entry.query.filters || {}) };
    setDraft(form); setDraftQ(entry.query.q || ''); setMode(entry.query.mode || 'simple');
    apply({ q: entry.query.q || '', mode: entry.query.mode || 'simple', form });
    notify(`Loaded "${entry.name}"`);
  }

  async function deleteSearch(id) {
    const entry = (saved.data || []).find((item) => String(item.id) === id);
    if (!entry || !window.confirm(`Delete saved search "${entry.name}"?`)) return;
    try {
      await api.delete(`/saved-searches/${entry.id}`);
      client.invalidateQueries({ queryKey: ['saved-searches', module.key] });
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function exportCsv() {
    setExporting(true);
    try {
      const columns = (preference.data?.columns?.length ? preference.data.columns : module.defaultColumns).join(',');
      await downloadFile(`/modules/${module.key}/export`, `${module.key}.csv`, { ...params, columns, format: 'csv' });
    } catch (error) {
      notify(error.message, 'error');
    } finally {
      setExporting(false);
    }
  }

  const [savedChoice, setSavedChoice] = useState('');
  const dirty = JSON.stringify({ q: draftQ.trim(), form: draft, mode }) !== JSON.stringify({ q: applied.q, form: applied.form, mode: applied.mode });
  const active = countActive(module, applied.form) + (applied.q ? 1 : 0);
  const advancedHelp = module.source === 'wazuh'
    ? 'Wazuh query language, e.g. os.platform=windows;version<4.9 or (status=disconnected,status=never_connected)'
    : 'Lucene syntax, e.g. rule.level:>=10 AND agent.name:web* · NOT rule.groups:syscheck · data.srcip:"10.0.0.5"';

  return (
    <>
      {/* Section 1: search bar */}
      <form className="panel search-bar" onSubmit={(event) => { event.preventDefault(); apply(); }}>
        <div className="query-row">
          <div className="query-input">
            <Search size={15} />
            <input value={draftQ} onChange={(event) => setDraftQ(event.target.value)} maxLength={1000}
              placeholder={mode === 'advanced' ? advancedHelp : module.source === 'wazuh' ? 'Search agent name, IP, OS, version…' : 'Search text, field:value, wildcards, "phrases"…'} aria-label="Search query" />
          </div>
          <button className="primary"><Search size={14} /> Search</button>
          <button type="button" className={`secondary ${mode === 'advanced' ? 'toggled' : ''}`} onClick={() => setMode(mode === 'advanced' ? 'simple' : 'advanced')} aria-pressed={mode === 'advanced'}>
            <SlidersHorizontal size={14} /> {mode === 'advanced' ? 'Advanced: on' : 'Advanced'}
          </button>
        </div>
        <div className="query-hints"><span>{mode === 'advanced' ? advancedHelp : 'Simple search: words are combined with AND. Use quotes for phrases and * as a wildcard. Enable Advanced for full query syntax.'}</span></div>
      </form>

      {/* Section 2: common filters */}
      <form className="panel filter-panel" onSubmit={(event) => { event.preventDefault(); apply(); }}>
        <div className="section-label"><Filter size={12} /> Filters · {rangeLabel(range)}</div>
        <div className="filter-grid">
          {module.filters.map((filter) => (
            <FilterInput key={filter.key} module={module} filter={filter} range={range} value={draft[filter.key]} onChange={(value) => setDraft({ ...draft, [filter.key]: value })} />
          ))}
        </div>
        {/* Section 3: search actions */}
        <div className="filter-actions">
          <span className="muted">{active ? `${active} active filter${active > 1 ? 's' : ''}` : 'No filters applied'}{dirty ? ' · changes not applied' : ''}</span>
          <select className="compact-select" value={savedChoice} onChange={(event) => { setSavedChoice(event.target.value); loadSearch(event.target.value); }} aria-label="Saved searches">
            <option value="">{saved.data?.length ? `Saved searches (${saved.data.length})` : 'No saved searches'}</option>
            {(saved.data || []).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </select>
          {savedChoice && <button type="button" className="icon-button" onClick={() => { deleteSearch(savedChoice); setSavedChoice(''); }} aria-label="Delete saved search"><Trash2 size={13} /></button>}
          <button type="button" className="secondary" onClick={clearAll}><RotateCcw size={13} /> Clear all</button>
          <button type="button" className="secondary" onClick={saveSearch}><Bookmark size={13} /> Save search</button>
          <button type="button" className="secondary" disabled={exporting} onClick={exportCsv}><FileBarChart size={13} /> {exporting ? 'Exporting…' : 'Export CSV'}</button>
          <button className="primary"><Save size={13} /> Apply filters</button>
        </div>
      </form>

      {/* Sections 4: search analytics (primary bar graph first, always visible) */}
      <div className="search-summary">
        <b>{aggregations.isLoading ? '…' : fmtNumber(aggregations.data?.total || 0)}</b>
        <span>matching records {aggregations.isFetching && !aggregations.isLoading ? '· updating…' : ''}</span>
        {module.kpis.slice(1).map((kpi) => <span key={kpi.key} className={`summary-chip tone-${kpi.tone || 'none'}`}>{kpi.label}: <b>{fmtNumber(aggregations.data?.kpis?.[kpi.key] ?? 0)}</b></span>)}
      </div>
      <div className="module-chart-grid search-charts">
        <ChartCard chart={module.primaryChart} result={aggregations} height={300} primary className="wide"
          onSelect={(chart, bucket) => { const filters = drillFilter(module, chart, bucket); if (filters) { const form = { ...applied.form, ...filters }; setDraft(form); apply({ ...applied, form }); } }} />
        {module.searchCharts.map((chart) => <ChartCard key={chart.key} chart={chart} result={aggregations} height={200} />)}
      </div>

      {/* Section 5: detailed records, same parameters as the charts */}
      <DataTable module={module} params={params} tableKey="search" title={`Matching ${module.source === 'wazuh' ? 'agents' : 'records'}`} onOpen={setSelected} />
      <RecordDrawer module={module} record={selected} onClose={() => setSelected(null)} onFilter={addFilter} />
    </>
  );
}
