import React from 'react';
import { Activity, ShieldAlert, Siren, AlertTriangle, ShieldCheck } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Empty, ErrorState, Loading, SeverityBadge } from '../../components/common.jsx';
import { fmtDate, fmtNumber, SERIES_COLORS, SEVERITIES } from '../../lib/format.js';

const SEVERITY_COLOR = Object.fromEntries(SEVERITIES.map((item) => [item.key, item.color]));
const STATUS_COLORS = { Active: '#25a37e', Disconnected: '#d03b3b', 'Never connected': '#fab219', Pending: '#8190a4' };
const axis = { tickLine: false, axisLine: false, tick: { fill: 'var(--muted)', fontSize: 10 } };
const tooltipStyle = { contentStyle: { background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text)', fontSize: 11 }, labelStyle: { color: 'var(--muted)' }, cursor: { fill: 'var(--panel2)' } };

/**
 * Widget catalog. `source` decides which request feeds the widget:
 * 'alerts' → GET /dashboard (OpenSearch), 'agents' → GET /agents/summary (Wazuh).
 */
export const WIDGETS = {
  total_alerts: { label: 'Total security alerts', source: 'alerts', width: 1, kind: 'kpi' },
  critical_alerts: { label: 'Critical alerts', source: 'alerts', width: 1, kind: 'kpi' },
  high_alerts: { label: 'High severity alerts', source: 'alerts', width: 1, kind: 'kpi' },
  medium_alerts: { label: 'Medium severity alerts', source: 'alerts', width: 1, kind: 'kpi' },
  low_alerts: { label: 'Low severity alerts', source: 'alerts', width: 1, kind: 'kpi' },
  alert_trend: { label: 'Alert trends over time', source: 'alerts', width: 4 },
  severity_distribution: { label: 'Severity distribution', source: 'alerts', width: 2 },
  top_agents: { label: 'Top 10 agents generating alerts', source: 'alerts', width: 2 },
  top_rules: { label: 'Top 10 Wazuh rules', source: 'alerts', width: 2 },
  top_srcips: { label: 'Top source IP addresses', source: 'alerts', width: 1 },
  top_dstips: { label: 'Top destination IP addresses', source: 'alerts', width: 1 },
  recent_alerts: { label: 'Recent security alerts', source: 'alerts', width: 4 },
  agent_inventory: { label: 'Agent inventory summary', source: 'agents', width: 2 },
  agent_status: { label: 'Agent connectivity status', source: 'agents', width: 2 },
  event_trends: { label: 'Security event trends (top rule groups)', source: 'alerts', width: 4 },
};

export const DEFAULT_WIDGETS = [
  'total_alerts', 'critical_alerts', 'high_alerts', 'medium_alerts', 'alert_trend', 'severity_distribution', 'agent_status',
  'top_agents', 'top_rules', 'top_srcips', 'top_dstips', 'event_trends', 'recent_alerts', 'agent_inventory',
].map((type) => ({ widget_type: type, width: WIDGETS[type].width, height: 1, config: {} }));

function bucketLabel(key, interval) {
  const date = new Date(key);
  if (interval === '1d') return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  if (interval === '12h') return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' });
  if (interval === '1m' || interval === '5m') return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function KpiWidget({ type, data }) {
  const meta = {
    total_alerts: ['Total alerts', data.total_events, 'All rule levels in range', Activity, 0],
    critical_alerts: ['Critical', data.severity_summary?.critical, 'Rule level 15', ShieldAlert, 1],
    high_alerts: ['High', data.severity_summary?.high, 'Rule level 12–14', Siren, 2],
    medium_alerts: ['Medium', data.severity_summary?.medium, 'Rule level 7–11', AlertTriangle, 3],
    low_alerts: ['Low', data.severity_summary?.low, 'Rule level 0–6', ShieldCheck, 3],
  }[type];
  const [label, value, note, Icon, tone] = meta;
  return (
    <div className={`kpi-card kpi-${tone} widget-kpi`}>
      <div className="kpi-head"><span>{label}</span><Icon size={16} /></div>
      <div className="kpi-value">{fmtNumber(value || 0)}</div>
      <div className="kpi-foot"><span>{note}</span></div>
    </div>
  );
}

function SeverityLegend() {
  return (
    <div className="chart-legend">
      {SEVERITIES.map((item) => <span key={item.key}><i style={{ background: item.color }} />{item.label}</span>)}
    </div>
  );
}

function AlertTrend({ data }) {
  const rows = (data.timeline || []).map((bucket) => ({ time: bucketLabel(bucket.key, data.range?.interval), ...Object.fromEntries(SEVERITIES.map((item) => [item.key, bucket[item.key] || 0])) }));
  if (!rows.some((row) => SEVERITIES.some((item) => row[item.key]))) return <Empty message="No alerts in this time range." />;
  // Stack bottom→top from low to critical so the most severe band sits on top.
  return (
    <>
      <SeverityLegend />
      <div className="chart-area tall"><ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} barCategoryGap={1}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" vertical={false} />
          <XAxis dataKey="time" {...axis} minTickGap={24} />
          <YAxis {...axis} allowDecimals={false} width={40} />
          <Tooltip {...tooltipStyle} />
          {[...SEVERITIES].reverse().map((item) => <Bar key={item.key} dataKey={item.key} name={item.label} stackId="s" fill={item.color} stroke="var(--panel)" strokeWidth={1} maxBarSize={22} />)}
        </BarChart>
      </ResponsiveContainer></div>
    </>
  );
}

function SeverityDistribution({ data, onDrill }) {
  const rows = SEVERITIES.map((item) => ({ key: item.key, name: `${item.label} (${item.levels})`, value: data.severity_summary?.[item.key] || 0 }));
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  if (!total) return <Empty message="No alerts in this time range." />;
  return (
    <div className="donut-wrap">
      <ResponsiveContainer width="55%" height="100%">
        <PieChart>
          <Pie data={rows} dataKey="value" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} stroke="var(--panel)" strokeWidth={2} onClick={(entry) => onDrill('severity', entry.key)}>
            {rows.map((row) => <Cell key={row.key} fill={SEVERITY_COLOR[row.key]} cursor="pointer" />)}
          </Pie>
          <Tooltip {...tooltipStyle} formatter={(value) => `${fmtNumber(value)} (${((value / total) * 100).toFixed(1)}%)`} />
        </PieChart>
      </ResponsiveContainer>
      <div className="legend-list">
        {rows.map((row) => (
          <button key={row.key} className="legend-button" onClick={() => onDrill('severity', row.key)}>
            <i style={{ background: SEVERITY_COLOR[row.key] }} />{row.name}<b>{fmtNumber(row.value)}</b>
          </button>
        ))}
      </div>
    </div>
  );
}

function TopAgents({ data, onDrill }) {
  const rows = (data.agents || []).map((bucket) => ({ name: bucket.key, alerts: bucket.doc_count }));
  if (!rows.length) return <Empty message="No agent activity in this range." />;
  return (
    <div className="chart-area"><ResponsiveContainer width="100%" height="100%">
      <BarChart data={rows} layout="vertical" margin={{ left: 4, right: 16 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" horizontal={false} />
        <XAxis type="number" {...axis} allowDecimals={false} />
        <YAxis type="category" dataKey="name" width={110} {...axis} />
        <Tooltip {...tooltipStyle} />
        <Bar dataKey="alerts" name="Alerts" fill={SERIES_COLORS[0]} radius={[0, 4, 4, 0]} barSize={12} cursor="pointer" onClick={(entry) => onDrill('agent', entry.name)} />
      </BarChart>
    </ResponsiveContainer></div>
  );
}

function RankList({ rows, onPick, render }) {
  if (!rows.length) return <Empty message="No data in this time range." />;
  const max = Math.max(...rows.map((row) => row.doc_count), 1);
  return (
    <div className="rank-list">
      {rows.map((row, index) => (
        <button key={row.key} className="rank-button" onClick={() => onPick(row)} title="Show matching alerts">
          <span className="rank-num">{String(index + 1).padStart(2, '0')}</span>
          <span className="rank-name">{render ? render(row) : row.key}<i className="rank-bar" style={{ width: `${(row.doc_count / max) * 100}%` }} /></span>
          <span className="rank-count">{fmtNumber(row.doc_count)}</span>
        </button>
      ))}
    </div>
  );
}

function EventTrends({ data }) {
  const groups = data.event_trends || [];
  if (!groups.length) return <Empty message="No rule-group activity in this range." />;
  const rows = (groups[0].timeline || []).map((bucket, index) => ({
    time: bucketLabel(bucket.key, data.range?.interval),
    ...Object.fromEntries(groups.map((group) => [group.key, group.timeline[index]?.doc_count || 0])),
  }));
  return (
    <div className="chart-area tall"><ResponsiveContainer width="100%" height="100%">
      <LineChart data={rows}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" vertical={false} />
        <XAxis dataKey="time" {...axis} minTickGap={24} />
        <YAxis {...axis} allowDecimals={false} width={40} />
        <Tooltip {...tooltipStyle} cursor={{ stroke: 'var(--faint)' }} />
        <Legend wrapperStyle={{ fontSize: 10, color: 'var(--muted)' }} iconType="plainline" />
        {groups.map((group, index) => <Line key={group.key} type="monotone" dataKey={group.key} stroke={SERIES_COLORS[index % SERIES_COLORS.length]} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />)}
      </LineChart>
    </ResponsiveContainer></div>
  );
}

function RecentAlerts({ data, onSelectAlert }) {
  const rows = data.recent || [];
  if (!rows.length) return <Empty message="No recent alerts." />;
  return (
    <div className="table-scroll">
      <table>
        <thead><tr><th>Time</th><th>Level</th><th>Rule</th><th>Description</th><th>Agent</th><th>Source IP</th></tr></thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row._id} className="click-row" onClick={() => onSelectAlert(row)}>
              <td className="timestamp">{fmtDate(row['@timestamp'])}</td>
              <td><SeverityBadge level={row.rule?.level} /></td>
              <td><code>{row.rule?.id}</code></td>
              <td className="event-desc">{row.rule?.description}</td>
              <td>{row.agent?.name}</td>
              <td className="mono">{row.data?.srcip || '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AgentStatus({ agents }) {
  const rows = [['Active', agents.active], ['Disconnected', agents.disconnected], ['Never connected', agents.never_connected], ['Pending', agents.pending]]
    .map(([name, value]) => ({ name, value: value || 0 }));
  if (!agents.total) return <Empty message="No agents registered." />;
  return (
    <div className="donut-wrap">
      <ResponsiveContainer width="55%" height="100%">
        <PieChart>
          <Pie data={rows} dataKey="value" nameKey="name" innerRadius={48} outerRadius={72} paddingAngle={2} stroke="var(--panel)" strokeWidth={2}>
            {rows.map((row) => <Cell key={row.name} fill={STATUS_COLORS[row.name]} />)}
          </Pie>
          <Tooltip {...tooltipStyle} />
        </PieChart>
      </ResponsiveContainer>
      <div className="legend-list">
        {rows.map((row) => <div key={row.name}><i style={{ background: STATUS_COLORS[row.name] }} />{row.name}<b>{fmtNumber(row.value)}</b></div>)}
      </div>
    </div>
  );
}

function AgentInventory({ agents }) {
  return (
    <div className="inventory-widget">
      <div className="inventory-total"><b>{fmtNumber(agents.total)}</b><span>registered agents</span></div>
      <div className="inventory-split">
        <div><span>Active</span><b>{fmtNumber(agents.active)}</b></div>
        <div><span>Disconnected</span><b>{fmtNumber(agents.disconnected)}</b></div>
        <div><span>Never connected</span><b>{fmtNumber(agents.never_connected)}</b></div>
      </div>
      <h4>Platforms</h4>
      {(agents.platforms || []).length ? (agents.platforms || []).map((item) => (
        <div className="detail-row" key={item.key}><span>{item.key}</span><b>{fmtNumber(item.doc_count)}</b></div>
      )) : <span className="muted">No platform data</span>}
    </div>
  );
}

/** Render one widget body. `alerts` / `agents` are react-query results. */
export function WidgetBody({ widget, alerts, agents, onDrill, onSelectAlert }) {
  const definition = WIDGETS[widget.widget_type];
  if (!definition) return <Empty message="Unknown widget type." />;
  const source = definition.source === 'agents' ? agents : alerts;
  if (source.isLoading) return <Loading />;
  if (source.error) return <ErrorState error={source.error} hint={definition.source === 'agents' ? 'Wazuh Manager API unavailable.' : 'OpenSearch unavailable.'} />;
  const data = source.data || {};
  switch (widget.widget_type) {
    case 'total_alerts': case 'critical_alerts': case 'high_alerts': case 'medium_alerts': case 'low_alerts':
      return <KpiWidget type={widget.widget_type} data={data} />;
    case 'alert_trend': return <AlertTrend data={data} />;
    case 'severity_distribution': return <SeverityDistribution data={data} onDrill={onDrill} />;
    case 'top_agents': return <TopAgents data={data} onDrill={onDrill} />;
    case 'top_rules': return <RankList rows={data.top_rules || []} onPick={(row) => onDrill('rule_id', row.key)} render={(row) => <><code>{row.key}</code> {row.description} <SeverityBadge level={row.level} /></>} />;
    case 'top_srcips': return <RankList rows={data.top_srcips || []} onPick={(row) => onDrill('srcip', row.key)} />;
    case 'top_dstips': return <RankList rows={data.top_dstips || []} onPick={(row) => onDrill('dstip', row.key)} />;
    case 'recent_alerts': return <RecentAlerts data={data} onSelectAlert={onSelectAlert} />;
    case 'event_trends': return <EventTrends data={data} />;
    case 'agent_status': return <AgentStatus agents={data} />;
    case 'agent_inventory': return <AgentInventory agents={data} />;
    default: return null;
  }
}
