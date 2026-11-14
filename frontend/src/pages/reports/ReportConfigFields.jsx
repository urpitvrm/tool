import React from 'react';
import { ChipToggle, Field } from '../../components/common.jsx';
import { SEVERITIES, splitList } from '../../lib/format.js';

export const EMPTY_FILTER_FORM = { severity: [], agent: '', ruleId: '', srcip: '', dstip: '', q: '', status: [] };

export const PERIOD_LABELS = {
  last_24h: 'Last 24 hours', last_7d: 'Last 7 days', last_30d: 'Last 30 days',
  previous_day: 'Previous day', previous_week: 'Previous week (Mon–Sun)', previous_month: 'Previous calendar month',
};

const AGENT_STATUSES = [
  { key: 'active', label: 'Active', tone: 'low' }, { key: 'disconnected', label: 'Disconnected', tone: 'critical' },
  { key: 'never_connected', label: 'Never connected', tone: 'medium' }, { key: 'pending', label: 'Pending', tone: 'muted' },
];

/** Form strings → API filter object (arrays). */
export function toApiFilters(form) {
  return {
    severity: form.severity, status: form.status, q: form.q.trim(),
    agent: splitList(form.agent), ruleId: splitList(form.ruleId), srcip: splitList(form.srcip), dstip: splitList(form.dstip),
  };
}

export function fromApiFilters(filters = {}) {
  const join = (value) => (Array.isArray(value) ? value.join(', ') : value || '');
  return {
    severity: filters.severity || [], status: filters.status || [], q: filters.q || '',
    agent: join(filters.agent), ruleId: join(filters.ruleId), srcip: join(filters.srcip), dstip: join(filters.dstip),
  };
}

export function describeFilters(filters = {}) {
  const parts = [];
  if (filters.severity?.length) parts.push(`severity: ${filters.severity.join(', ')}`);
  if (filters.agent?.length) parts.push(`agent: ${filters.agent.join(', ')}`);
  if (filters.ruleId?.length) parts.push(`rule: ${filters.ruleId.join(', ')}`);
  if (filters.srcip?.length) parts.push(`src: ${filters.srcip.join(', ')}`);
  if (filters.dstip?.length) parts.push(`dst: ${filters.dstip.join(', ')}`);
  if (filters.status?.length) parts.push(`status: ${filters.status.join(', ')}`);
  if (filters.q) parts.push(`query: "${filters.q}"`);
  return parts.join(' · ') || 'No additional filters';
}

/** Filters and column selection for one report type. */
export default function ReportConfigFields({ type, filters, onFilters, columns, onColumns }) {
  if (!type) return null;
  const set = (key) => (event) => onFilters({ ...filters, [key]: event.target.value });
  const locked = type.lockedFilters || [];
  const allSelected = type.columns.length && type.columns.every((column) => columns.includes(column.key));
  return (
    <>
      {type.supportsFilters ? (
        <div className="filter-grid">
          <Field label="Severity" className="span-2" hint={locked.includes('severity') ? 'Fixed by this report type' : type.key.endsWith('_security') ? 'Defaults to critical + high when empty' : undefined}>
            <ChipToggle disabled={locked.includes('severity')} options={SEVERITIES.map((item) => ({ key: item.key, label: `${item.label} · ${item.levels}` }))} value={filters.severity} onChange={(severity) => onFilters({ ...filters, severity })} />
          </Field>
          <Field label="Agents" hint="Names, IDs or wildcards, comma-separated"><input value={filters.agent} onChange={set('agent')} placeholder="e.g. 001, web-*" /></Field>
          <Field label="Rule IDs"><input value={filters.ruleId} onChange={set('ruleId')} placeholder="e.g. 5710, 5712" /></Field>
          <Field label="Source IPs"><input value={filters.srcip} onChange={set('srcip')} placeholder="e.g. 10.0.0.*" /></Field>
          <Field label="Destination IPs"><input value={filters.dstip} onChange={set('dstip')} placeholder="e.g. 192.168.1.10" /></Field>
          <Field label="Query" className="span-2" hint="OpenSearch simple query string"><input value={filters.q} onChange={set('q')} placeholder='e.g. rule.groups:sshd AND "Failed password"' maxLength={500} /></Field>
        </div>
      ) : (
        <div className="filter-grid">
          <Field label="Agent status" className="span-2"><ChipToggle options={AGENT_STATUSES} value={filters.status} onChange={(status) => onFilters({ ...filters, status })} /></Field>
          <Field label="Agents" className="span-2" hint="Names or IDs, comma-separated"><input value={filters.agent} onChange={set('agent')} placeholder="e.g. 001, db-server" /></Field>
        </div>
      )}
      {type.columns.length > 0 && (
        <Field label={`Columns (${columns.length || type.defaultColumns.length} selected)`} className="columns-field">
          <div className="column-picker">
            <button type="button" className="text-button" onClick={() => onColumns(allSelected ? type.defaultColumns : type.columns.map((column) => column.key))}>
              {allSelected ? 'Reset to defaults' : 'Select all'}
            </button>
            {type.columns.map((column) => (
              <label key={column.key} className="check-inline">
                <input type="checkbox" checked={columns.includes(column.key)}
                  onChange={(event) => onColumns(event.target.checked ? [...columns, column.key] : columns.filter((key) => key !== column.key))} />
                {column.label}
              </label>
            ))}
          </div>
        </Field>
      )}
    </>
  );
}
