import React, { useEffect, useMemo, useState } from 'react';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, Columns3, FileBarChart, FileSpreadsheet, GripVertical, Plus, RotateCcw, Search, X } from 'lucide-react';
import { api, apiError } from '../api.js';
import { Empty, ErrorState, Loading, Modal, Pagination, SeverityBadge, StatusPill, useToast } from './common.jsx';
import { getPath } from './RecordDrawers.jsx';
import { downloadFile, fmtDate, fmtNumber } from '../lib/format.js';

function Cell({ column, record }) {
  const value = getPath(record, column.key);
  if (value == null || value === '') return <td className="muted">—</td>;
  if (column.key === 'rule.level') return <td><SeverityBadge level={value} /></td>;
  if (column.key === 'status' || column.key === 'data.sca.check.result') return <td><StatusPill status={value} /></td>;
  if (column.type === 'date') return <td className="timestamp">{fmtDate(value)}</td>;
  if (Array.isArray(value)) return <td className="cell-wrap">{value.join(', ')}</td>;
  if (typeof value === 'object') return <td className="mono cell-wrap">{JSON.stringify(value)}</td>;
  if (column.type === 'number') return <td className="mono">{typeof value === 'number' ? fmtNumber(value) : value}</td>;
  const mono = /ip$|\.id$|^id$|port|md5|sha|cve|path/i.test(column.key);
  return <td className={`${mono ? 'mono' : ''} ${column.type === 'text' ? 'event-desc' : 'cell-wrap'}`} title={String(value)}>{String(value)}</td>;
}

/**
 * Module data table. `params` must be the same filter params used for the charts.
 * Sorting, paging and exports are server-side; column choices persist per user/module/table.
 */
export default function DataTable({ module, params, tableKey = 'search', title = 'Matching records', onOpen }) {
  const client = useQueryClient();
  const { notify } = useToast();
  const [sort, setSort] = useState(module.defaultSort);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(25);
  const [choosing, setChoosing] = useState(false);
  const [exporting, setExporting] = useState('');

  const preferenceKey = ['table-pref', module.key, tableKey];
  const preference = useQuery({ queryKey: preferenceKey, queryFn: () => api.get(`/modules/${module.key}/preferences/${tableKey}`).then((r) => r.data), staleTime: Infinity });
  const fields = useQuery({ queryKey: ['module-fields', module.key], queryFn: () => api.get(`/modules/${module.key}/fields`).then((r) => r.data), staleTime: 600_000 });
  const fieldMap = useMemo(() => new Map([...(fields.data || module.fields)].map((item) => [item.key, item])), [fields.data, module.fields]);
  const columnKeys = preference.data?.columns?.length ? preference.data.columns : module.defaultColumns;
  const columns = columnKeys.map((key) => fieldMap.get(key) || { key, label: key, type: 'keyword', sortable: false });

  useEffect(() => { if (preference.data?.page_size) setSize(preference.data.page_size); }, [preference.data?.page_size]);
  // Any change to filters returns to the first page.
  const filterKey = JSON.stringify(params);
  useEffect(() => { setPage(1); }, [filterKey]);

  const query = { ...params, page, size, sort: sort.field, order: sort.order };
  const records = useQuery({
    queryKey: ['module-records', module.key, query],
    queryFn: () => api.get(`/modules/${module.key}/records`, { params: query }).then((r) => r.data),
    placeholderData: keepPreviousData,
  });

  async function savePreference(nextColumns, pageSize = size) {
    try {
      const { data } = await api.put(`/modules/${module.key}/preferences/${tableKey}`, { columns: nextColumns, page_size: pageSize });
      client.setQueryData(preferenceKey, data);
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function resetPreference() {
    try {
      await api.delete(`/modules/${module.key}/preferences/${tableKey}`);
      client.setQueryData(preferenceKey, { columns: null });
      setSize(25);
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function exportAs(format) {
    setExporting(format);
    try {
      await downloadFile(`/modules/${module.key}/export`, `${module.key}.${format}`, { ...params, sort: sort.field, order: sort.order, columns: columnKeys.join(','), format });
    } catch (error) {
      notify(error.message, 'error');
    } finally {
      setExporting('');
    }
  }

  const toggleSort = (column) => {
    if (!column.sortable) return;
    setSort((current) => ({ field: column.key, order: current.field === column.key && current.order === 'desc' ? 'asc' : 'desc' }));
    setPage(1);
  };
  const items = records.data?.items || [];

  return (
    <div className="panel table-panel module-table">
      <div className="table-toolbar">
        <div><b>{title}</b><span>{fmtNumber(records.data?.total || 0)} records · sorted by {fieldMap.get(sort.field)?.label || sort.field} ({sort.order === 'asc' ? 'ascending' : 'descending'}){records.isFetching && !records.isLoading ? ' · updating…' : ''}</span></div>
        <div className="table-tools">
          <button className="secondary" onClick={() => setChoosing(true)}><Columns3 size={14} /> Select columns</button>
          <button className="secondary" disabled={!!exporting} onClick={() => exportAs('csv')}><FileBarChart size={14} /> {exporting === 'csv' ? 'Exporting…' : 'CSV'}</button>
          <button className="secondary" disabled={!!exporting} onClick={() => exportAs('xlsx')}><FileSpreadsheet size={14} /> {exporting === 'xlsx' ? 'Exporting…' : 'Excel'}</button>
        </div>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key} aria-sort={sort.field === column.key ? (sort.order === 'asc' ? 'ascending' : 'descending') : undefined}>
                  {column.sortable ? (
                    <button className={`sort-header ${sort.field === column.key ? 'active' : ''}`} onClick={() => toggleSort(column)} title={`Sort by ${column.label}`}>
                      {column.label}{sort.field === column.key ? (sort.order === 'asc' ? <ArrowUp size={10} /> : <ArrowDown size={10} />) : <span className="sort-hint">↕</span>}
                    </button>
                  ) : column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {records.isLoading ? <tr><td colSpan={columns.length}><Loading /></td></tr>
              : records.error ? <tr><td colSpan={columns.length}><ErrorState error={records.error} /></td></tr>
                : items.length ? items.map((record, index) => (
                  <tr key={record._id || record.id || index} className={onOpen ? 'click-row' : ''} onClick={() => onOpen?.(record)}>
                    {columns.map((column) => <Cell key={column.key} column={column} record={record} />)}
                  </tr>
                )) : <tr><td colSpan={columns.length}><Empty message="No records match the current filters and time range." /></td></tr>}
          </tbody>
        </table>
      </div>
      <Pagination page={page} size={size} total={records.data?.total || 0} maxWindow={records.data?.max_window} onPage={setPage}
        onSize={(value) => { setSize(value); setPage(1); savePreference(columnKeys, value); }} />
      {choosing && (
        <ColumnChooser fields={fields.data || module.fields} loadingFields={fields.isLoading} selected={columnKeys} defaults={module.defaultColumns}
          onClose={() => setChoosing(false)} onSave={(next) => { savePreference(next); setChoosing(false); }} onReset={() => { resetPreference(); setChoosing(false); }} />
      )}
    </div>
  );
}

function ColumnChooser({ fields, loadingFields, selected, defaults, onClose, onSave, onReset }) {
  const [order, setOrder] = useState(selected);
  const [filter, setFilter] = useState('');
  const [dragIndex, setDragIndex] = useState(null);
  const byKey = useMemo(() => new Map(fields.map((item) => [item.key, item])), [fields]);
  const available = fields.filter((item) => !order.includes(item.key) && (!filter || `${item.key} ${item.label}`.toLowerCase().includes(filter.toLowerCase())));
  const catalog = available.filter((item) => !item.discovered);
  const discovered = available.filter((item) => item.discovered);
  const move = (from, to) => {
    if (to < 0 || to >= order.length) return;
    const next = [...order];
    const [item] = next.splice(from, 1);
    next.splice(to, 0, item);
    setOrder(next);
  };
  const label = (key) => byKey.get(key)?.label || key;

  return (
    <Modal title="Select columns" eyebrow="TABLE" onClose={onClose} wide
      footer={<>
        <button type="button" className="secondary" onClick={onReset}><RotateCcw size={13} /> Reset to defaults</button>
        <span className="spacer" />
        <button type="button" className="secondary" onClick={onClose}>Cancel</button>
        <button type="button" className="primary" disabled={!order.length} onClick={() => onSave(order)}>Save columns</button>
      </>}>
      <div className="column-chooser">
        <div>
          <h4 className="form-section">Visible columns ({order.length}) · drag or use arrows to reorder</h4>
          <ol className="column-order">
            {order.map((key, index) => (
              <li key={key} draggable onDragStart={() => setDragIndex(index)} onDragOver={(event) => event.preventDefault()}
                onDrop={() => { move(dragIndex, index); setDragIndex(null); }} className={dragIndex === index ? 'dragging' : ''}>
                <GripVertical size={13} className="grip" aria-hidden="true" />
                <span title={key}>{label(key)}{!defaults.includes(key) && <small className="muted"> · {key}</small>}</span>
                <button className="icon-button" onClick={() => move(index, index - 1)} disabled={index === 0} aria-label={`Move ${label(key)} up`}><ArrowUp size={12} /></button>
                <button className="icon-button" onClick={() => move(index, index + 1)} disabled={index === order.length - 1} aria-label={`Move ${label(key)} down`}><ArrowDown size={12} /></button>
                <button className="icon-button" onClick={() => setOrder(order.filter((item) => item !== key))} disabled={order.length === 1} aria-label={`Hide ${label(key)}`}><X size={12} /></button>
              </li>
            ))}
          </ol>
        </div>
        <div>
          <h4 className="form-section">Available fields</h4>
          <div className="query-input"><Search size={13} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter fields…" /></div>
          <div className="field-list">
            {loadingFields && <Loading label="Loading index fields…" />}
            {catalog.map((item) => (
              <button key={item.key} className="field-add" onClick={() => setOrder([...order, item.key])}><Plus size={12} /> {item.label}<small>{item.key}</small></button>
            ))}
            {discovered.length > 0 && <div className="field-group">All indexed fields</div>}
            {discovered.slice(0, 300).map((item) => (
              <button key={item.key} className="field-add" onClick={() => setOrder([...order, item.key])}><Plus size={12} /> {item.key}<small>{item.type}{item.sortable ? '' : ' · not sortable'}</small></button>
            ))}
            {discovered.length > 300 && <p className="muted note-line">{discovered.length - 300} more fields. Type to filter.</p>}
            {!loadingFields && !available.length && <p className="muted note-line">No more fields{filter ? ' match' : ''}.</p>}
          </div>
        </div>
      </div>
    </Modal>
  );
}
