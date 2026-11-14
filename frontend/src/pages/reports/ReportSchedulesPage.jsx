import React, { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, CalendarClock, Download, History, Mail, Pause, Pencil, Play, Plus, RefreshCw, RotateCcw, Send, Trash2 } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { Drawer, Empty, ErrorState, Field, Loading, Modal, PageHeading, Pagination, Segmented, StatusPill, useToast } from '../../components/common.jsx';
import { fmtDate, splitList } from '../../lib/format.js';
import { browserTimezone, timezoneOptions } from '../../lib/time.js';
import ReportConfigFields, { EMPTY_FILTER_FORM, PERIOD_LABELS, describeFilters, fromApiFilters, toApiFilters } from './ReportConfigFields.jsx';
import { downloadReport, useReportCatalog } from './ReportsPage.jsx';

const FREQUENCIES = [{ key: 'daily', label: 'Daily' }, { key: 'weekly', label: 'Weekly' }, { key: 'monthly', label: 'Monthly' }, { key: 'cron', label: 'Custom cron' }];
const WEEKDAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const DEFAULT_PERIOD = { daily: 'previous_day', weekly: 'previous_week', monthly: 'previous_month', cron: 'last_24h' };

export function describeCadence(schedule) {
  const time = `${schedule.start_time} ${schedule.timezone}`;
  const start = new Date(`${schedule.start_date}T00:00:00`);
  if (schedule.frequency === 'daily') return `Daily at ${time}`;
  if (schedule.frequency === 'weekly') return `Every ${WEEKDAYS[start.getDay()]} at ${time}`;
  if (schedule.frequency === 'monthly') return start.getDate() > 28 ? `Last day of each month at ${time}` : `Monthly on day ${start.getDate()} at ${time}`;
  return `Cron "${schedule.cron_expression}" (${schedule.timezone})`;
}

function emptyForm(types) {
  const type = types.find((item) => item.key === 'daily_security') || types[0];
  return {
    name: 'Daily security report', report_type: type?.key, format: 'pdf', frequency: 'daily', cron_expression: '',
    start_date: new Date().toISOString().slice(0, 10), start_time: '07:00', timezone: browserTimezone(), end_date: '',
    recipients: '', cc: '', bcc: '', email_subject: 'Daily security report', email_message: 'Please find the latest security report attached.',
    delivery_method: 'attachment', status: 'active', period: 'previous_day', filters: EMPTY_FILTER_FORM, columns: type?.defaultColumns || [],
  };
}

function formFromSchedule(schedule) {
  const join = (list) => (list || []).join(', ');
  return {
    ...schedule, cron_expression: schedule.cron_expression || '', end_date: schedule.end_date || '',
    recipients: join(schedule.recipients), cc: join(schedule.cc), bcc: join(schedule.bcc),
    status: schedule.status === 'completed' ? 'paused' : schedule.status,
    period: schedule.report_config?.period || DEFAULT_PERIOD[schedule.frequency],
    filters: fromApiFilters(schedule.report_config?.filters), columns: schedule.report_config?.columns || [],
  };
}

export default function ReportSchedulesPage() {
  const catalog = useReportCatalog();
  const { notify } = useToast();
  const client = useQueryClient();
  const schedules = useQuery({ queryKey: ['report-schedules'], queryFn: () => api.get('/report-schedules').then((r) => r.data), refetchInterval: 30_000 });
  const [editing, setEditing] = useState(null); // { id?, form }
  const [historyFor, setHistoryFor] = useState(null);
  const types = catalog.data?.types || [];
  const capabilities = catalog.data?.capabilities || {};
  const typeLabel = (key) => types.find((item) => item.key === key)?.label || key;
  const refresh = () => client.invalidateQueries({ queryKey: ['report-schedules'] });

  async function act(schedule, action) {
    try {
      if (action === 'delete') {
        if (!window.confirm(`Delete schedule "${schedule.name}"? Its execution history is kept.`)) return;
        await api.delete(`/report-schedules/${schedule.id}`);
        notify('Schedule deleted');
      } else if (action === 'run') {
        await api.post(`/report-schedules/${schedule.id}/run`);
        notify('Run queued. The report is generated within the next scheduler cycle.');
      } else {
        await api.post(`/report-schedules/${schedule.id}/${action}`);
        notify(action === 'pause' ? 'Schedule paused' : 'Schedule resumed');
      }
      refresh();
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  if (catalog.isLoading) return <Loading />;
  if (catalog.error) return <ErrorState error={catalog.error} />;
  const rows = schedules.data || [];

  return (
    <>
      <PageHeading title="Report Scheduling" eyebrow="OPERATIONS" description="Automatically generate reports and deliver them by email. Schedules are stored in PostgreSQL and survive restarts.">
        <button className="secondary" onClick={refresh}><RefreshCw size={14} /> Refresh</button>
        <button className="primary" onClick={() => setEditing({ form: emptyForm(types) })}><Plus size={14} /> New schedule</button>
      </PageHeading>

      {!capabilities.smtp_configured && (
        <div className="notice-banner warn"><AlertTriangle size={15} /><span>SMTP is not configured on the server (SMTP_HOST / SMTP_FROM). Scheduled reports will be generated, but email delivery will fail until it is configured.</span></div>
      )}

      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr><th>Schedule</th><th>Report</th><th>Cadence</th><th>Recipients</th><th>Status</th><th>Next run</th><th>Last run</th><th /></tr></thead>
            <tbody>
              {schedules.isLoading ? <tr><td colSpan={8}><Loading /></td></tr>
                : schedules.error ? <tr><td colSpan={8}><ErrorState error={schedules.error} /></td></tr>
                  : rows.length ? rows.map((schedule) => (
                    <tr key={schedule.id}>
                      <td><b>{schedule.name}</b><small className="cell-sub">{schedule.created_by_username ? `by ${schedule.created_by_username}` : ''}</small></td>
                      <td>{typeLabel(schedule.report_type)}<small className="cell-sub">{schedule.format.toUpperCase()} · {schedule.delivery_method === 'link' ? 'secure link' : 'attachment'}</small></td>
                      <td>{describeCadence(schedule)}{schedule.end_date && <small className="cell-sub">until {schedule.end_date}</small>}</td>
                      <td title={[...schedule.recipients, ...schedule.cc, ...schedule.bcc].join(', ')}>{schedule.recipients[0]}{schedule.recipients.length > 1 && <small className="cell-sub">+{schedule.recipients.length - 1} more{schedule.cc.length + schedule.bcc.length ? `, ${schedule.cc.length + schedule.bcc.length} cc/bcc` : ''}</small>}</td>
                      <td><StatusPill status={schedule.status} /></td>
                      <td className="timestamp">{schedule.next_run_at ? fmtDate(schedule.next_run_at) : '—'}</td>
                      <td className="timestamp">{schedule.last_run_at ? fmtDate(schedule.last_run_at) : '—'}{schedule.last_status && <small className="cell-sub"><StatusPill status={schedule.last_status} /></small>}</td>
                      <td className="row-actions">
                        <button className="icon-button" title="Edit" onClick={() => setEditing({ id: schedule.id, form: formFromSchedule(schedule) })}><Pencil size={13} /></button>
                        {schedule.status === 'active'
                          ? <button className="icon-button" title="Pause" onClick={() => act(schedule, 'pause')}><Pause size={13} /></button>
                          : <button className="icon-button" title="Resume" onClick={() => act(schedule, 'resume')}><Play size={13} /></button>}
                        <button className="icon-button" title="Run now" onClick={() => act(schedule, 'run')}><Send size={13} /></button>
                        <button className="icon-button" title="Execution history" onClick={() => setHistoryFor(schedule)}><History size={13} /></button>
                        <button className="icon-button" title="Delete" onClick={() => act(schedule, 'delete')}><Trash2 size={13} /></button>
                      </td>
                    </tr>
                  )) : <tr><td colSpan={8}><Empty title="No schedules" message="Create a schedule to deliver reports automatically." /></td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {editing && <ScheduleForm initial={editing} types={types} capabilities={capabilities} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />}
      {historyFor && <ExecutionHistory schedule={historyFor} onClose={() => setHistoryFor(null)} />}
    </>
  );
}

function ScheduleForm({ initial, types, capabilities, onClose, onSaved }) {
  const [form, setForm] = useState(initial.form);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const zones = useMemo(timezoneOptions, []);
  const { notify } = useToast();
  const type = types.find((item) => item.key === form.report_type);
  const set = (key) => (event) => setForm({ ...form, [key]: event.target.value });
  const manage = capabilities.manage;

  function changeType(key) {
    const next = types.find((item) => item.key === key);
    setForm({ ...form, report_type: key, columns: next?.defaultColumns || [], filters: EMPTY_FILTER_FORM, name: form.name || next?.label });
  }

  function changeFrequency(frequency) {
    // Keep the reporting period aligned with the cadence unless the user picked something else.
    const period = form.period === DEFAULT_PERIOD[form.frequency] ? DEFAULT_PERIOD[frequency] : form.period;
    setForm({ ...form, frequency, period });
  }

  async function submit(event) {
    event.preventDefault();
    setError('');
    setSaving(true);
    const body = {
      name: form.name.trim(), report_type: form.report_type, format: form.format, frequency: form.frequency,
      cron_expression: form.frequency === 'cron' ? form.cron_expression.trim() : null,
      start_date: form.start_date, start_time: form.start_time.slice(0, 5), timezone: form.timezone, end_date: form.end_date || null,
      recipients: splitList(form.recipients), cc: manage ? splitList(form.cc) : [], bcc: manage ? splitList(form.bcc) : [],
      email_subject: form.email_subject.trim(), email_message: form.email_message, delivery_method: form.delivery_method, status: form.status,
      report_config: { filters: toApiFilters(form.filters), columns: form.columns, ...(type?.periodless ? {} : { period: form.period }) },
    };
    try {
      if (initial.id) await api.put(`/report-schedules/${initial.id}`, body);
      else await api.post('/report-schedules', body);
      notify(initial.id ? 'Schedule updated' : 'Schedule created');
      onSaved();
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal title={initial.id ? 'Edit schedule' : 'New report schedule'} eyebrow="REPORT SCHEDULING" onClose={onClose} wide>
      <form onSubmit={submit} className="schedule-form">
        <h4 className="form-section">1 · Report</h4>
        <div className="filter-grid">
          <Field label="Schedule name" className="span-2"><input required maxLength={200} value={form.name} onChange={set('name')} /></Field>
          <Field label="Report type"><select value={form.report_type} onChange={(event) => changeType(event.target.value)}>{types.map((item) => <option key={item.key} value={item.key}>{item.label}</option>)}</select></Field>
          <Field label="Format"><Segmented options={[{ key: 'pdf', label: 'PDF' }, { key: 'xlsx', label: 'Excel' }, { key: 'csv', label: 'CSV' }]} value={form.format} onChange={(format) => setForm({ ...form, format })} /></Field>
          {!type?.periodless && (
            <Field label="Report period" hint="Evaluated in the schedule time zone at each run" className="span-2">
              <select value={form.period} onChange={set('period')}>{Object.entries(PERIOD_LABELS).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select>
            </Field>
          )}
        </div>
        <details className="config-details">
          <summary>Filters &amp; columns <span className="muted">· {describeFilters(toApiFilters(form.filters))}</span></summary>
          <ReportConfigFields type={type} filters={form.filters} onFilters={(filters) => setForm({ ...form, filters })} columns={form.columns} onColumns={(columns) => setForm({ ...form, columns })} />
        </details>

        <h4 className="form-section">2 · Schedule</h4>
        <div className="filter-grid">
          <Field label="Frequency" className="span-2">
            <Segmented options={FREQUENCIES.filter((item) => item.key !== 'cron' || manage || form.frequency === 'cron')} value={form.frequency} onChange={changeFrequency} />
          </Field>
          {form.frequency === 'cron' && (
            <Field label="Cron expression" className="span-2" hint="minute hour day-of-month month day-of-week · at most every 15 minutes">
              <input required value={form.cron_expression} onChange={set('cron_expression')} placeholder="0 6 * * 1-5" className="mono" />
            </Field>
          )}
          <Field label="Start date" hint={form.frequency === 'weekly' ? `Runs every ${WEEKDAYS[new Date(`${form.start_date}T00:00:00`).getDay()]}` : form.frequency === 'monthly' ? 'Runs on this day of the month (29–31 → last day)' : undefined}>
            <input type="date" required value={form.start_date} onChange={set('start_date')} />
          </Field>
          <Field label="Time"><input type="time" required value={form.start_time} onChange={set('start_time')} /></Field>
          <Field label="Time zone"><select value={form.timezone} onChange={set('timezone')}>{zones.map((zone) => <option key={zone}>{zone}</option>)}</select></Field>
          <Field label="End date (optional)"><input type="date" value={form.end_date} min={form.start_date} onChange={set('end_date')} /></Field>
          <Field label="Status"><Segmented options={[{ key: 'active', label: 'Active' }, { key: 'paused', label: 'Paused' }]} value={form.status} onChange={(status) => setForm({ ...form, status })} /></Field>
        </div>

        <h4 className="form-section">3 · Email delivery</h4>
        <div className="filter-grid">
          <Field label="Recipients" className="span-2" hint={capabilities.allowed_email_domains?.length ? `Allowed domains: ${capabilities.allowed_email_domains.join(', ')}` : 'Comma-separated email addresses'}>
            <textarea required rows={2} value={form.recipients} onChange={set('recipients')} placeholder="soc@example.com, lead@example.com" />
          </Field>
          {manage && (
            <>
              <Field label="CC"><input value={form.cc} onChange={set('cc')} placeholder="optional" /></Field>
              <Field label="BCC"><input value={form.bcc} onChange={set('bcc')} placeholder="optional" /></Field>
            </>
          )}
          <Field label="Subject" className="span-2"><input required maxLength={200} value={form.email_subject} onChange={set('email_subject')} /></Field>
          <Field label="Message" className="span-2"><textarea rows={3} maxLength={5000} value={form.email_message} onChange={set('email_message')} /></Field>
          <Field label="Delivery" className="span-2" hint="Files larger than the attachment limit are always sent as a secure, expiring link.">
            <Segmented options={[{ key: 'attachment', label: 'Attach report' }, { key: 'link', label: 'Secure download link' }]} value={form.delivery_method} onChange={(delivery_method) => setForm({ ...form, delivery_method })} />
          </Field>
        </div>
        {error && <ErrorState error={error} title="Schedule could not be saved" hint="" />}
        <div className="modal-actions">
          <button type="button" className="secondary" onClick={onClose}>Cancel</button>
          <button className="primary" disabled={saving}><CalendarClock size={14} /> {saving ? 'Saving…' : initial.id ? 'Save changes' : 'Create schedule'}</button>
        </div>
      </form>
    </Modal>
  );
}

function ExecutionHistory({ schedule, onClose }) {
  const [page, setPage] = useState(1);
  const { notify } = useToast();
  const executions = useQuery({
    queryKey: ['schedule-executions', schedule.id, page],
    queryFn: () => api.get(`/report-schedules/${schedule.id}/executions`, { params: { page, size: 20 } }).then((r) => r.data),
    refetchInterval: (query) => (query.state.data?.items?.some((item) => ['queued', 'running', 'retrying'].includes(item.status)) ? 5000 : false),
  });

  async function retry(execution) {
    try {
      await api.post(`/report-schedules/executions/${execution.id}/retry`);
      notify(execution.stage === 'email' ? 'Email delivery retry queued' : 'Report generation retry queued');
      executions.refetch();
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  return (
    <Drawer title={schedule.name} eyebrow="EXECUTION HISTORY" onClose={onClose}>
      <div className="drawer-meta"><StatusPill status={schedule.status} /><span className="muted">{describeCadence(schedule)}</span></div>
      {executions.isLoading ? <Loading /> : executions.error ? <ErrorState error={executions.error} /> : executions.data.items.length ? (
        <div className="execution-list">
          {executions.data.items.map((execution) => (
            <div key={execution.id} className="execution-item">
              <div className="execution-head">
                <StatusPill status={execution.status} />
                <b>{fmtDate(execution.scheduled_for)}</b>
                <span className="muted">{execution.trigger === 'manual' ? 'manual run' : 'scheduled'} · attempt {execution.attempts}/{execution.max_attempts}</span>
              </div>
              {execution.error && <p className="execution-error">{execution.stage === 'email' ? 'Email: ' : 'Generation: '}{execution.error}</p>}
              {execution.status === 'retrying' && <p className="muted">Next attempt {fmtDate(execution.next_attempt_at)}</p>}
              {execution.deliveries.map((delivery) => (
                <div key={delivery.id} className="delivery-row">
                  <Mail size={12} /><StatusPill status={delivery.status} />
                  <span>{delivery.recipients.length + delivery.cc.length + delivery.bcc.length} recipient(s) · {delivery.delivery_method}</span>
                  <span className="muted">{fmtDate(delivery.created_at)}</span>
                  {delivery.error && <small className="execution-error">{delivery.error}</small>}
                </div>
              ))}
              <div className="execution-actions">
                {execution.downloadable && <button className="text-button" onClick={() => downloadReport({ id: execution.report_history_id, file_name: execution.file_name, format: execution.format }).catch((error) => notify(error.message, 'error'))}><Download size={12} /> Download report</button>}
                {['failed', 'email_failed'].includes(execution.status) && <button className="text-button" onClick={() => retry(execution)}><RotateCcw size={12} /> Retry {execution.stage === 'email' ? 'email delivery' : 'generation'}</button>}
              </div>
            </div>
          ))}
          <Pagination page={page} size={20} total={executions.data.total} onPage={setPage} />
        </div>
      ) : <Empty title="No executions yet" message={schedule.next_run_at ? `First run ${fmtDate(schedule.next_run_at)}.` : 'Resume the schedule or use Run now.'} />}
    </Drawer>
  );
}
