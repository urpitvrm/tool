import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { Activity, CircleOff, PlugZap, RefreshCw, Search, Server, Siren, Unplug } from 'lucide-react';
import { api } from '../api.js';
import { Drawer, Empty, ErrorState, Loading, PageHeading, Pagination, Segmented, SortHeader, StatusPill } from '../components/common.jsx';
import { fmtDate, fmtNumber } from '../lib/format.js';

const STATUS_CARDS = [
  ['', 'Total agents', Server, 'total'],
  ['active', 'Active', Activity, 'active'],
  ['disconnected', 'Disconnected', Unplug, 'disconnected'],
  ['never_connected', 'Never connected', CircleOff, 'never_connected'],
  ['pending', 'Pending', PlugZap, 'pending'],
];

const COLUMNS = [['ID', 'id'], ['Name', 'name'], ['IP address', 'ip'], ['Operating system', 'os.name'], ['Version', 'version'], ['Groups', 'group'], ['Status', 'status'], ['Last keep-alive', 'lastKeepAlive']];

export default function AgentsPage() {
  const [status, setStatus] = useState('');
  const [searchDraft, setSearchDraft] = useState('');
  const [search, setSearch] = useState('');
  const [group, setGroup] = useState('');
  const [platform, setPlatform] = useState('');
  const [hideManager, setHideManager] = useState(true);
  const [page, setPage] = useState(1);
  const [size, setSize] = useState(25);
  const [sort, setSort] = useState({ field: 'id', order: 'asc' });
  const [selected, setSelected] = useState(null);

  const summary = useQuery({ queryKey: ['agents-summary'], queryFn: () => api.get('/agents/summary').then((r) => r.data), refetchInterval: 60_000 });
  const groups = useQuery({ queryKey: ['agent-groups'], queryFn: () => api.get('/agent-groups').then((r) => r.data), staleTime: 300_000 });
  const params = useMemo(() => ({
    page, size, sort: sort.field, order: sort.order, exclude_manager: hideManager,
    ...(search ? { search } : {}), ...(status ? { status } : {}), ...(group ? { group } : {}), ...(platform ? { platform } : {}),
  }), [page, size, sort, hideManager, search, status, group, platform]);
  const agents = useQuery({ queryKey: ['agents', params], queryFn: () => api.get('/agents', { params }).then((r) => r.data), placeholderData: keepPreviousData });

  const reset = (fn) => (value) => { fn(value); setPage(1); };
  const rows = agents.data?.items || [];

  return (
    <>
      <PageHeading title="Agent Inventory" eyebrow="INFRASTRUCTURE" description="Live agent inventory from the Wazuh Manager API (source of truth).">
        <button className="secondary" onClick={() => { summary.refetch(); agents.refetch(); }}><RefreshCw size={14} /> Refresh</button>
      </PageHeading>

      {summary.error ? <ErrorState error={summary.error} /> : (
        <div className="kpi-grid kpi-5">
          {STATUS_CARDS.map(([key, label, Icon, field], index) => (
            <button key={label} className={`kpi-card kpi-${index} kpi-button ${status === key ? 'selected' : ''}`} onClick={() => reset(setStatus)(key)}>
              <div className="kpi-head"><span>{label}</span><Icon size={16} /></div>
              <div className="kpi-value">{summary.isLoading ? '…' : fmtNumber(summary.data?.[field])}</div>
              <div className="kpi-foot"><span>{key ? 'Click to filter' : 'Excludes the manager'}</span></div>
            </button>
          ))}
        </div>
      )}

      <div className="panel filter-panel">
        <div className="toolbar-row">
          <form className="query-input" onSubmit={(event) => { event.preventDefault(); reset(setSearch)(searchDraft.trim()); }}>
            <Search size={14} />
            <input value={searchDraft} onChange={(event) => setSearchDraft(event.target.value)} placeholder="Search name, IP, ID, OS, version… (Enter)" maxLength={120} />
          </form>
          <select className="compact-select" value={status} onChange={(event) => reset(setStatus)(event.target.value)} aria-label="Status">
            <option value="">All statuses</option>
            <option value="active">Active</option><option value="disconnected">Disconnected</option>
            <option value="never_connected">Never connected</option><option value="pending">Pending</option>
          </select>
          <select className="compact-select" value={group} onChange={(event) => reset(setGroup)(event.target.value)} aria-label="Group">
            <option value="">All groups</option>
            {(groups.data?.items || []).map((item) => <option key={item.name} value={item.name}>{item.name} ({item.count})</option>)}
          </select>
          <select className="compact-select" value={platform} onChange={(event) => reset(setPlatform)(event.target.value)} aria-label="Platform">
            <option value="">All platforms</option>
            {(summary.data?.platforms || []).map((item) => <option key={item.key} value={item.key}>{item.key} ({item.doc_count})</option>)}
          </select>
          <label className="check-inline"><input type="checkbox" checked={hideManager} onChange={(event) => reset(setHideManager)(event.target.checked)} /> Hide manager (000)</label>
        </div>
      </div>

      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr>{COLUMNS.map(([label, field]) => <SortHeader key={label} label={label} field={field} sort={sort} onSort={(next) => reset(setSort)(next)} />)}</tr></thead>
            <tbody>
              {agents.isLoading ? <tr><td colSpan={COLUMNS.length}><Loading /></td></tr>
                : agents.error ? <tr><td colSpan={COLUMNS.length}><ErrorState error={agents.error} /></td></tr>
                  : rows.length ? rows.map((agent) => (
                    <tr key={agent.id} className="click-row" onClick={() => setSelected(agent)}>
                      <td><code>{agent.id}</code></td>
                      <td>{agent.name}</td>
                      <td className="mono">{agent.ip || '—'}</td>
                      <td>{agent.os?.name || '—'}<small className="cell-sub">{agent.os?.version}</small></td>
                      <td>{agent.version || '—'}</td>
                      <td>{(agent.group || []).join(', ') || '—'}</td>
                      <td><StatusPill status={agent.status} /></td>
                      <td className="timestamp">{fmtDate(agent.lastKeepAlive)}</td>
                    </tr>
                  )) : <tr><td colSpan={COLUMNS.length}><Empty message="No agents match the current filters." /></td></tr>}
            </tbody>
          </table>
        </div>
        <Pagination page={page} size={size} total={agents.data?.total || 0} onPage={setPage} onSize={reset(setSize)} />
      </div>
      {selected && <AgentDrawer agentId={selected.id} initial={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function AgentDrawer({ agentId, initial, onClose }) {
  const [tab, setTab] = useState('details');
  const navigate = useNavigate();
  const detail = useQuery({ queryKey: ['agent', agentId], queryFn: () => api.get(`/agents/${agentId}`).then((r) => r.data), initialData: initial });
  const agent = detail.data || initial;
  const rows = [
    ['Agent ID', agent.id], ['Name', agent.name], ['Status', agent.status], ['IP address', agent.ip], ['Registration IP', agent.registerIP],
    ['Operating system', agent.os?.name], ['OS version', agent.os?.version], ['Platform', agent.os?.platform], ['Architecture', agent.os?.arch],
    ['Agent version', agent.version], ['Groups', (agent.group || []).join(', ')], ['Group config', agent.group_config_status],
    ['Manager', agent.manager], ['Node', agent.node_name], ['Registered', fmtDate(agent.dateAdd)], ['Last keep-alive', fmtDate(agent.lastKeepAlive)],
  ];
  return (
    <Drawer title={agent.name} eyebrow={`AGENT ${agent.id}`} onClose={onClose}
      actions={<button className="secondary wide" onClick={() => navigate(`/alerts?agent=${encodeURIComponent(agent.name)}`)}><Siren size={13} /> View alerts from this agent</button>}>
      <div className="drawer-meta"><StatusPill status={agent.status} /></div>
      <Segmented options={[{ key: 'details', label: 'Details' }, { key: 'json', label: 'Raw JSON' }]} value={tab} onChange={setTab} />
      {detail.error && <ErrorState error={detail.error} />}
      {tab === 'json' ? <pre className="json-view">{JSON.stringify(agent, null, 2)}</pre> : (
        <div className="detail-sections"><section>
          {rows.filter(([, value]) => value).map(([label, value]) => <div className="detail-row" key={label}><span>{label}</span><b>{value}</b></div>)}
        </section></div>
      )}
    </Drawer>
  );
}
