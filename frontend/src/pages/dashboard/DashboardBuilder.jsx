import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowLeft, ArrowRight, GripVertical, LayoutDashboard, Minus, Pencil, Plus, RefreshCw, Save, Star, Trash2, X } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { Empty, ErrorState, Field, Modal, PageHeading, PanelTitle, TimeRangePicker, useToast } from '../../components/common.jsx';
import { AlertDrawer } from '../AlertsPage.jsx';
import { rangeLabel, rangeParams } from '../../lib/time.js';
import { DEFAULT_WIDGETS, WIDGETS, WidgetBody } from './widgets.jsx';

const REFRESH_OPTIONS = [[0, 'Off'], [30, '30 s'], [60, '1 min'], [300, '5 min'], [900, '15 min']];
const clone = (widgets) => widgets.map((widget) => ({ widget_type: widget.widget_type, title: widget.title || null, width: widget.width || 1, height: widget.height || 1, config: widget.config || {} }));

export default function DashboardBuilder({ range: globalRange }) {
  const navigate = useNavigate();
  const client = useQueryClient();
  const { notify } = useToast();
  const list = useQuery({ queryKey: ['custom-dashboards'], queryFn: () => api.get('/custom-dashboards').then((r) => r.data) });
  const dashboards = list.data || [];

  const [activeId, setActiveId] = useState(null);
  const active = dashboards.find((item) => String(item.id) === String(activeId)) || null;
  const [widgets, setWidgets] = useState(clone(DEFAULT_WIDGETS));
  const [range, setRange] = useState(globalRange);
  const [refresh, setRefresh] = useState(60);
  const [editing, setEditing] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [adding, setAdding] = useState(false);
  const [naming, setNaming] = useState(null); // { mode: 'create' | 'rename', name }
  const [dragIndex, setDragIndex] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);

  // Pick the default (or first) saved dashboard once the list arrives.
  useEffect(() => {
    if (activeId == null && dashboards.length) setActiveId((dashboards.find((item) => item.is_default) || dashboards[0]).id);
  }, [dashboards, activeId]);

  // Load a dashboard's saved widgets and settings when switching.
  useEffect(() => {
    if (!active) return;
    setWidgets(active.widgets?.length ? clone(active.widgets) : clone(DEFAULT_WIDGETS));
    if (active.layout?.range?.preset) setRange(active.layout.range);
    if (active.layout?.refresh != null) setRefresh(active.layout.refresh);
    setDirty(false);
    setEditing(false);
  }, [active?.id, active?.updated_at]); // eslint-disable-line react-hooks/exhaustive-deps

  const needsAlerts = widgets.some((widget) => WIDGETS[widget.widget_type]?.source === 'alerts');
  const needsAgents = widgets.some((widget) => WIDGETS[widget.widget_type]?.source === 'agents');
  const params = useMemo(() => rangeParams(range), [range]);
  const interval = refresh ? refresh * 1000 : false;
  const alerts = useQuery({ queryKey: ['dashboard-data', params], queryFn: () => api.get('/dashboard', { params }).then((r) => r.data), enabled: needsAlerts, refetchInterval: interval });
  const agents = useQuery({ queryKey: ['agents-summary'], queryFn: () => api.get('/agents/summary').then((r) => r.data), enabled: needsAgents, refetchInterval: interval });

  const change = (next) => { setWidgets(next); setDirty(true); };
  const move = (from, to) => {
    if (to < 0 || to >= widgets.length || from === to) return;
    const next = [...widgets];
    const [item] = next.splice(from, 1);
    next.splice(to, 0, item);
    change(next);
  };
  const resize = (index, delta) => change(widgets.map((widget, i) => (i === index ? { ...widget, width: Math.min(4, Math.max(1, widget.width + delta)) } : widget)));
  const remove = (index) => change(widgets.filter((_, i) => i !== index));

  const drill = (key, value) => navigate(`/alerts?${new URLSearchParams({ [key]: value })}`);
  const layout = () => ({ range, refresh });

  async function save() {
    try {
      if (active) {
        await api.put(`/custom-dashboards/${active.id}`, { widgets, layout: layout() });
      } else {
        const { data } = await api.post('/custom-dashboards', { name: 'My SOC dashboard', is_default: true, widgets, layout: layout() });
        setActiveId(data.id);
      }
      await client.invalidateQueries({ queryKey: ['custom-dashboards'] });
      setDirty(false);
      setEditing(false);
      notify('Dashboard saved');
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function submitName(event) {
    event.preventDefault();
    try {
      if (naming.mode === 'create') {
        const { data } = await api.post('/custom-dashboards', { name: naming.name, widgets: clone(DEFAULT_WIDGETS), layout: { range: globalRange, refresh: 60 }, is_default: !dashboards.length });
        setActiveId(data.id);
      } else {
        await api.put(`/custom-dashboards/${active.id}`, { name: naming.name });
      }
      await client.invalidateQueries({ queryKey: ['custom-dashboards'] });
      setNaming(null);
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function removeDashboard() {
    if (!active || !window.confirm(`Delete dashboard "${active.name}"?`)) return;
    try {
      await api.delete(`/custom-dashboards/${active.id}`);
      setActiveId(null);
      await client.invalidateQueries({ queryKey: ['custom-dashboards'] });
      notify('Dashboard deleted');
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function makeDefault() {
    try {
      await api.put(`/custom-dashboards/${active.id}`, { is_default: true });
      await client.invalidateQueries({ queryKey: ['custom-dashboards'] });
      notify(`"${active.name}" is now your default dashboard`);
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  return (
    <>
      <PageHeading title={active?.name || 'SOC Dashboard'} eyebrow="OVERVIEW" description={`Live security telemetry · ${rangeLabel(range)}${refresh ? ` · refreshes every ${REFRESH_OPTIONS.find(([s]) => s === refresh)?.[1]}` : ''}`}>
        <TimeRangePicker value={range} onChange={(next) => { setRange(next); setDirty(true); }} />
        <select className="compact-select" value={refresh} onChange={(event) => { setRefresh(Number(event.target.value)); setDirty(true); }} aria-label="Auto refresh">
          {REFRESH_OPTIONS.map(([seconds, label]) => <option key={seconds} value={seconds}>Refresh: {label}</option>)}
        </select>
        <button className="secondary" onClick={() => { alerts.refetch(); agents.refetch(); }} title="Refresh now"><RefreshCw size={14} /></button>
        {editing
          ? <button className="primary" onClick={save}><Save size={14} /> Save</button>
          : <button className="secondary" onClick={() => setEditing(true)}><Pencil size={14} /> Customize</button>}
      </PageHeading>

      <div className="dashboard-toolbar">
        <div className="dashboard-tabs" role="tablist">
          {list.isLoading ? <span className="muted">Loading dashboards…</span> : dashboards.map((item) => (
            <button key={item.id} role="tab" aria-selected={item.id === active?.id} className={item.id === active?.id ? 'on' : ''}
              onClick={() => (!dirty || window.confirm('Discard unsaved changes?')) && setActiveId(item.id)}>
              {item.is_default && <Star size={11} />} {item.name}
            </button>
          ))}
          {!list.isLoading && !dashboards.length && <span className="muted">Default layout (not saved yet)</span>}
          <button className="tab-add" onClick={() => setNaming({ mode: 'create', name: '' })}><Plus size={12} /> New dashboard</button>
        </div>
        {dirty && <span className="unsaved">Unsaved changes</span>}
        {active && (
          <div className="dashboard-actions">
            {!active.is_default && <button className="text-button" onClick={makeDefault}><Star size={12} /> Set default</button>}
            <button className="text-button" onClick={() => setNaming({ mode: 'rename', name: active.name })}><Pencil size={12} /> Rename</button>
            <button className="text-button danger" onClick={removeDashboard}><Trash2 size={12} /> Delete</button>
          </div>
        )}
      </div>

      {list.error && <ErrorState error={list.error} title="Saved dashboards could not be loaded" />}
      {editing && (
        <div className="edit-banner">
          <span>Drag widgets to reorder, use the arrows to move, − / + to resize, and × to remove.</span>
          <button className="secondary" onClick={() => setAdding(true)}><Plus size={13} /> Add widget</button>
          <button className="text-button" onClick={() => { setEditing(false); if (active) { setWidgets(clone(active.widgets?.length ? active.widgets : DEFAULT_WIDGETS)); setDirty(false); } }}>Cancel</button>
        </div>
      )}

      {!widgets.length ? <Empty title="This dashboard has no widgets" message="Choose Customize → Add widget to build it." /> : (
        <div className={`widget-grid ${editing ? 'editing' : ''}`}>
          {widgets.map((widget, index) => {
            const definition = WIDGETS[widget.widget_type] || { label: widget.widget_type };
            const kpi = definition.kind === 'kpi';
            return (
              <div
                key={`${widget.widget_type}-${index}`}
                className={`widget span-${widget.width} ${kpi ? 'widget-kpi-wrap' : 'panel chart-panel'} ${dragIndex === index ? 'dragging' : ''}`}
                draggable={editing}
                onDragStart={() => setDragIndex(index)}
                onDragOver={(event) => editing && event.preventDefault()}
                onDrop={() => { move(dragIndex, index); setDragIndex(null); }}
                onDragEnd={() => setDragIndex(null)}
              >
                {editing && (
                  <div className="widget-controls">
                    <GripVertical size={14} className="grip" aria-hidden="true" />
                    <button className="icon-button" onClick={() => move(index, index - 1)} aria-label="Move earlier"><ArrowLeft size={12} /></button>
                    <button className="icon-button" onClick={() => move(index, index + 1)} aria-label="Move later"><ArrowRight size={12} /></button>
                    <button className="icon-button" onClick={() => resize(index, -1)} disabled={widget.width <= 1} aria-label="Narrower"><Minus size={12} /></button>
                    <button className="icon-button" onClick={() => resize(index, 1)} disabled={widget.width >= 4} aria-label="Wider"><Plus size={12} /></button>
                    <button className="icon-button" onClick={() => remove(index)} aria-label="Remove widget"><X size={12} /></button>
                  </div>
                )}
                {!kpi && <PanelTitle title={widget.title || definition.label} tag={definition.source === 'agents' ? 'WAZUH API' : 'OPENSEARCH'} />}
                <WidgetBody widget={widget} alerts={alerts} agents={agents} onDrill={drill} onSelectAlert={setSelectedAlert} />
              </div>
            );
          })}
        </div>
      )}

      {adding && (
        <Modal title="Add widgets" eyebrow="DASHBOARD" onClose={() => setAdding(false)} wide>
          <div className="widget-catalog">
            {Object.entries(WIDGETS).map(([type, definition]) => {
              const count = widgets.filter((widget) => widget.widget_type === type).length;
              return (
                <button key={type} className="catalog-item" onClick={() => change([...widgets, { widget_type: type, width: definition.width, height: 1, config: {} }])}>
                  <LayoutDashboard size={15} />
                  <span><b>{definition.label}</b><small>{definition.source === 'agents' ? 'Wazuh Manager API' : 'OpenSearch alerts'}{count ? ` · on dashboard (${count})` : ''}</small></span>
                  <Plus size={14} />
                </button>
              );
            })}
          </div>
        </Modal>
      )}

      {naming && (
        <Modal title={naming.mode === 'create' ? 'New dashboard' : 'Rename dashboard'} eyebrow="DASHBOARD" onClose={() => setNaming(null)}>
          <form onSubmit={submitName}>
            <Field label="Name"><input autoFocus required maxLength={200} value={naming.name} onChange={(event) => setNaming({ ...naming, name: event.target.value })} /></Field>
            <div className="modal-actions"><button type="button" className="secondary" onClick={() => setNaming(null)}>Cancel</button><button className="primary">{naming.mode === 'create' ? 'Create' : 'Save'}</button></div>
          </form>
        </Modal>
      )}
      {selectedAlert && <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} onFilter={(key, value) => drill(key, value)} />}
    </>
  );
}
