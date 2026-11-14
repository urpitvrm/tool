import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { BookmarkPlus, CalendarClock, Download, FileBarChart, FileSpreadsheet, FileText, History, Trash2 } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { Empty, ErrorState, Field, Loading, PageHeading, PanelTitle, Segmented, StatusPill, useCurrentUser, useToast } from '../../components/common.jsx';
import { downloadFile, fmtBytes, fmtDate } from '../../lib/format.js';
import { browserTimezone, timezoneOptions, toLocalInput } from '../../lib/time.js';
import ReportConfigFields, { EMPTY_FILTER_FORM, PERIOD_LABELS, describeFilters, fromApiFilters, toApiFilters } from './ReportConfigFields.jsx';

export const FORMAT_OPTIONS = [{ key: 'pdf', label: 'PDF' }, { key: 'xlsx', label: 'Excel' }, { key: 'csv', label: 'CSV' }];
const FORMAT_ICON = { pdf: FileText, xlsx: FileSpreadsheet, csv: FileBarChart };

export function useReportCatalog() {
  return useQuery({ queryKey: ['report-catalog'], queryFn: () => api.get('/reports/catalog').then((r) => r.data), staleTime: 300_000 });
}

export async function downloadReport(record) {
  await downloadFile(`/report-history/${record.id}/download`, record.file_name || `report-${record.id}.${record.format}`);
}

export default function ReportsPage() {
  const catalog = useReportCatalog();
  const { can } = useCurrentUser();
  const { notify } = useToast();
  const client = useQueryClient();
  const types = catalog.data?.types || [];
  const zones = useMemo(timezoneOptions, []);

  const [typeKey, setTypeKey] = useState('daily_security');
  const type = types.find((item) => item.key === typeKey);
  const [name, setName] = useState('');
  const [format, setFormat] = useState('pdf');
  const [periodMode, setPeriodMode] = useState('preset');
  const [period, setPeriod] = useState('previous_day');
  const [start, setStart] = useState(toLocalInput(Date.now() - 86_400_000));
  const [end, setEnd] = useState(toLocalInput(Date.now()));
  const [timezone, setTimezone] = useState(browserTimezone());
  const [filters, setFilters] = useState(EMPTY_FILTER_FORM);
  const [columns, setColumns] = useState([]);
  const [busy, setBusy] = useState(false);
  const [lastError, setLastError] = useState('');

  const templates = useQuery({ queryKey: ['report-templates'], queryFn: () => api.get('/report-templates').then((r) => r.data) });
  const recent = useQuery({ queryKey: ['report-history', 'recent'], queryFn: () => api.get('/report-history', { params: { size: 6 } }).then((r) => r.data) });

  function selectType(key, keepConfig = false) {
    const next = types.find((item) => item.key === key);
    setTypeKey(key);
    if (!next) return;
    if (!keepConfig) {
      setName(next.label);
      setColumns(next.defaultColumns);
      setFilters(EMPTY_FILTER_FORM);
      if (next.defaultPeriod) { setPeriod(next.defaultPeriod); setPeriodMode('preset'); }
    }
  }
  useEffect(() => { if (types.length && !name) selectType(typeKey); }, [types.length]); // eslint-disable-line react-hooks/exhaustive-deps

  const customInvalid = periodMode === 'custom' && !(start && end && new Date(start) < new Date(end));

  function payload() {
    return {
      name: name.trim() || type?.label, report_type: typeKey, format, timezone, filters: toApiFilters(filters), columns,
      ...(type?.periodless ? {} : periodMode === 'custom' ? { start: new Date(start).toISOString(), end: new Date(end).toISOString() } : { period }),
    };
  }

  async function generate(event) {
    event.preventDefault();
    setBusy(true);
    setLastError('');
    try {
      const { data } = await api.post('/reports/generate', payload(), { timeout: 300_000 });
      await downloadReport(data);
      notify(`${data.name} generated (${fmtBytes(data.file_size)})`);
    } catch (error) {
      const message = error instanceof Error && !error.response ? error.message : apiError(error);
      setLastError(message);
      notify(message, 'error');
    } finally {
      setBusy(false);
      client.invalidateQueries({ queryKey: ['report-history'] });
    }
  }

  async function saveTemplate() {
    const templateName = window.prompt('Template name', name || type?.label);
    if (!templateName) return;
    try {
      const body = payload();
      await api.post('/report-templates', { name: templateName, report_type: typeKey, format, options: { filters: body.filters, columns, ...(body.period ? { period: body.period } : {}) } });
      client.invalidateQueries({ queryKey: ['report-templates'] });
      notify('Template saved');
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  function loadTemplate(template) {
    selectType(template.report_type, true);
    setName(template.name);
    setFormat(template.format);
    setFilters(fromApiFilters(template.options?.filters));
    setColumns(template.options?.columns?.length ? template.options.columns : types.find((item) => item.key === template.report_type)?.defaultColumns || []);
    if (template.options?.period) { setPeriodMode('preset'); setPeriod(template.options.period); }
    notify(`Loaded template "${template.name}"`);
  }

  async function deleteTemplate(template) {
    if (!window.confirm(`Delete template "${template.name}"?`)) return;
    try {
      await api.delete(`/report-templates/${template.id}`);
      client.invalidateQueries({ queryKey: ['report-templates'] });
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  if (catalog.isLoading) return <Loading />;
  if (catalog.error) return <ErrorState error={catalog.error} />;
  const canGenerate = can('reports:generate');

  return (
    <>
      <PageHeading title="Reports" eyebrow="OPERATIONS" description="Generate PDF, Excel and CSV security reports from OpenSearch alerts and the Wazuh agent inventory.">
        <Link className="secondary" to="/report-history"><History size={14} /> Report history</Link>
        {can('reports:schedule') && <Link className="secondary" to="/report-schedules"><CalendarClock size={14} /> Schedules</Link>}
      </PageHeading>

      <div className="report-layout">
        <div className="panel report-types">
          <PanelTitle title="Report type" subtitle={`${types.length} report types`} />
          <div className="type-list">
            {types.map((item) => (
              <button key={item.key} className={`type-item ${item.key === typeKey ? 'on' : ''}`} onClick={() => selectType(item.key)}>
                <b>{item.label}</b><small>{item.description}</small>
                <span className="panel-tag">{item.source === 'agents' ? 'WAZUH API' : 'OPENSEARCH'}</span>
              </button>
            ))}
          </div>
        </div>

        <form className="panel report-form" onSubmit={generate}>
          <PanelTitle title={type?.label || 'Report'} subtitle={type?.description} />
          <div className="filter-grid">
            <Field label="Report name" className="span-2"><input required maxLength={200} value={name} onChange={(event) => setName(event.target.value)} /></Field>
            <Field label="Output format"><Segmented options={FORMAT_OPTIONS} value={format} onChange={setFormat} /></Field>
            <Field label="Time zone" hint="Used for dates and relative periods">
              <select value={timezone} onChange={(event) => setTimezone(event.target.value)}>{zones.map((zone) => <option key={zone}>{zone}</option>)}</select>
            </Field>
            {!type?.periodless && (
              <>
                <Field label="Period">
                  <Segmented options={[{ key: 'preset', label: 'Relative' }, { key: 'custom', label: 'Custom dates' }]} value={periodMode} onChange={setPeriodMode} />
                </Field>
                {periodMode === 'preset' ? (
                  <Field label="Relative period">
                    <select value={period} onChange={(event) => setPeriod(event.target.value)}>
                      {Object.entries(PERIOD_LABELS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
                    </select>
                  </Field>
                ) : (
                  <Field label="Start → end" hint={customInvalid ? 'Start must be before end' : undefined}>
                    <div className="inline-pair">
                      <input type="datetime-local" value={start} onChange={(event) => setStart(event.target.value)} />
                      <input type="datetime-local" value={end} onChange={(event) => setEnd(event.target.value)} />
                    </div>
                  </Field>
                )}
              </>
            )}
            {type?.periodless && <div className="span-2 muted note-line">Inventory reports reflect the current state of all agents; no time period applies.</div>}
          </div>
          <h4 className="form-section">Filters &amp; columns</h4>
          <ReportConfigFields type={type} filters={filters} onFilters={setFilters} columns={columns} onColumns={setColumns} />
          {format === 'pdf' && <p className="muted note-line">PDF output includes up to {catalog.data.capabilities.pdf_max_rows.toLocaleString()} detail rows; Excel and CSV include up to {catalog.data.capabilities.max_rows.toLocaleString()}.</p>}
          {lastError && <ErrorState error={lastError} title="Report generation failed" hint="The failure was recorded in report history." />}
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={saveTemplate} disabled={!canGenerate}><BookmarkPlus size={14} /> Save as template</button>
            <button className="primary" disabled={busy || !canGenerate || customInvalid} title={canGenerate ? '' : 'Requires the reports:generate permission'}>
              <Download size={14} /> {busy ? 'Generating…' : 'Generate & download'}
            </button>
          </div>
        </form>

        <div className="report-side">
          <div className="panel side-card">
            <PanelTitle title="Templates" subtitle="Saved report configurations" />
            {templates.isLoading ? <Loading /> : templates.error ? <ErrorState error={templates.error} /> : templates.data.length ? (
              <div className="side-list">
                {templates.data.map((template) => (
                  <div key={template.id} className="side-item">
                    <button className="side-main" onClick={() => loadTemplate(template)} title={describeFilters(template.options?.filters)}>
                      <b>{template.name}</b><small>{types.find((item) => item.key === template.report_type)?.label} · {template.format.toUpperCase()}</small>
                    </button>
                    <button className="icon-button" onClick={() => deleteTemplate(template)} aria-label="Delete template"><Trash2 size={13} /></button>
                  </div>
                ))}
              </div>
            ) : <Empty title="No templates" message="Configure a report and choose Save as template." />}
          </div>
          <div className="panel side-card">
            <PanelTitle title="Recent reports"><Link className="text-button" to="/report-history">View all</Link></PanelTitle>
            {recent.isLoading ? <Loading /> : recent.error ? <ErrorState error={recent.error} /> : recent.data.items.length ? (
              <div className="side-list">
                {recent.data.items.map((record) => {
                  const Icon = FORMAT_ICON[record.format] || FileText;
                  return (
                    <div key={record.id} className="side-item">
                      <Icon size={15} className="muted" />
                      <div className="side-main"><b>{record.name}</b><small>{fmtDate(record.created_at)} · {fmtBytes(record.file_size)}</small></div>
                      {record.downloadable ? (
                        <button className="icon-button" onClick={() => downloadReport(record).catch((error) => notify(error.message, 'error'))} aria-label="Download"><Download size={13} /></button>
                      ) : <StatusPill status={record.status} />}
                    </div>
                  );
                })}
              </div>
            ) : <Empty title="No reports yet" message="Generated reports appear here." />}
          </div>
        </div>
      </div>
    </>
  );
}
