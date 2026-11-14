import React from 'react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Empty, ErrorState, Loading, PanelTitle } from './common.jsx';
import { fmtNumber, SERIES_COLORS, SEVERITIES, severityOf } from '../lib/format.js';

const SEVERITY_COLOR = Object.fromEntries(SEVERITIES.map((item) => [item.key, item.color]));
const OTHER_COLOR = '#6b7a8f';
const STATUS_COLOR = {
  active: '#25a37e', passed: '#25a37e', Successful: '#25a37e',
  disconnected: '#d03b3b', failed: '#d03b3b', Failed: '#d03b3b',
  never_connected: '#fab219', pending: OTHER_COLOR, 'not applicable': OTHER_COLOR,
};
const VULN_COLOR = { Critical: SEVERITY_COLOR.critical, High: SEVERITY_COLOR.high, Medium: SEVERITY_COLOR.medium, Low: SEVERITY_COLOR.low };
const MAX_SLICES = 5; // categorical hues are assigned in fixed order; the rest fold into "Other"

const axis = { tickLine: false, axisLine: false, tick: { fill: 'var(--muted)', fontSize: 10 } };
const tooltip = {
  contentStyle: { background: 'var(--panel)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--text)', fontSize: 11 },
  labelStyle: { color: 'var(--muted)' }, itemStyle: { color: 'var(--text)' }, cursor: { fill: 'var(--panel2)' },
};

function colorFor(chart, bucket, index) {
  switch (chart.colorBy) {
    case 'level': return SEVERITY_COLOR[severityOf(bucket.key)];
    case 'severity': return SEVERITY_COLOR[bucket.key] || OTHER_COLOR;
    case 'status': case 'outcome': return STATUS_COLOR[bucket.key] || OTHER_COLOR;
    case 'vulnSeverity': return VULN_COLOR[bucket.key] || OTHER_COLOR;
    default: return chart.kind === 'pie' || chart.kind === 'donut' ? SERIES_COLORS[index] || OTHER_COLOR : SERIES_COLORS[0];
  }
}

function timeLabel(time, interval) {
  const date = new Date(time);
  if (interval === '1d') return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  if (interval === '12h') return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' });
  if (interval === '1m' || interval === '5m') return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function SliceLegend({ rows, total, onSelect }) {
  return (
    <div className="legend-list">
      {rows.map((row) => (
        <button key={row.key} className="legend-button" disabled={!onSelect || row.other} onClick={() => onSelect?.(row)}>
          <i style={{ background: row.color }} /><span className="legend-name">{row.label}</span>
          <b>{fmtNumber(row.count)}</b><small>{total ? `${((row.count / total) * 100).toFixed(1)}%` : ''}</small>
        </button>
      ))}
    </div>
  );
}

function Categorical({ chart, data, onSelect, height }) {
  const pretty = (label) => (chart.colorBy === 'status' ? String(label).replace(/^\w/, (char) => char.toUpperCase()) : label);
  const buckets = data.buckets.map((bucket, index) => ({ ...bucket, label: pretty(bucket.label), color: colorFor(chart, bucket, index) }));
  if (!buckets.some((bucket) => bucket.count)) return <Empty message="No matching records for these filters." />;
  const select = onSelect ? (row) => !row.other && onSelect(chart, row) : undefined;

  if (chart.kind === 'pie' || chart.kind === 'donut') {
    const shown = buckets.slice(0, MAX_SLICES);
    const rest = buckets.slice(MAX_SLICES).reduce((sum, bucket) => sum + bucket.count, 0) + (data.other || 0);
    const rows = rest ? [...shown, { key: '__other', label: 'Other', count: rest, color: OTHER_COLOR, other: true }] : shown;
    const total = rows.reduce((sum, row) => sum + row.count, 0);
    return (
      <div className="donut-wrap" style={{ height }}>
        <ResponsiveContainer width="50%" height="100%">
          <PieChart>
            <Pie data={rows} dataKey="count" nameKey="label" innerRadius={chart.kind === 'donut' ? '58%' : 0} outerRadius="88%" paddingAngle={rows.length > 1 ? 2 : 0} stroke={rows.length > 1 ? "var(--panel)" : "none"} strokeWidth={2} onClick={select} cursor={onSelect ? 'pointer' : undefined}>
              {rows.map((row) => <Cell key={row.key} fill={row.color} />)}
            </Pie>
            <Tooltip {...tooltip} formatter={(value) => [`${fmtNumber(value)} (${((value / total) * 100).toFixed(1)}%)`, 'Records']} />
          </PieChart>
        </ResponsiveContainer>
        <SliceLegend rows={rows} total={total} onSelect={select} />
      </div>
    );
  }

  const horizontal = chart.kind === 'hbar';
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={buckets} layout={horizontal ? 'vertical' : 'horizontal'} margin={{ top: 8, right: 16, left: horizontal ? 4 : 8, bottom: chart.xLabel ? 18 : 4 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" vertical={horizontal} horizontal={!horizontal} />
          {horizontal ? (
            <>
              <XAxis type="number" {...axis} allowDecimals={false} />
              <YAxis type="category" dataKey="label" width={170} {...axis} interval={0} tickFormatter={(value) => (String(value).length > 28 ? `${String(value).slice(0, 27)}…` : value)} />
            </>
          ) : (
            <>
              <XAxis dataKey="label" {...axis} interval={0} tickFormatter={(value) => (String(value).length > 16 ? `${String(value).slice(0, 15)}…` : value)}
                label={chart.xLabel ? { value: chart.xLabel, position: 'insideBottom', offset: -12, fill: 'var(--muted)', fontSize: 10 } : undefined} />
              <YAxis {...axis} allowDecimals={false} width={48}
                label={chart.yLabel ? { value: chart.yLabel, angle: -90, position: 'insideLeft', fill: 'var(--muted)', fontSize: 10, style: { textAnchor: 'middle' } } : undefined} />
            </>
          )}
          <Tooltip {...tooltip} formatter={(value) => [fmtNumber(value), chart.yLabel || 'Records']} />
          <Bar dataKey="count" name={chart.yLabel || 'Records'} radius={horizontal ? [0, 4, 4, 0] : [4, 4, 0, 0]} maxBarSize={horizontal ? 14 : 56} onClick={select} cursor={onSelect ? 'pointer' : undefined}>
            {buckets.map((bucket) => <Cell key={bucket.key} fill={bucket.color} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function Series({ chart, data, interval, height }) {
  const rows = data.points.map((point) => ({ ...point, label: timeLabel(point.time, interval) }));
  if (!rows.some((row) => data.series.some((name) => row[name]))) return <Empty message="No matching records in this time range." />;
  const severity = chart.colorBy === 'severity';
  const color = (name, index) => (severity ? SEVERITY_COLOR[name] : SERIES_COLORS[index] || OTHER_COLOR);
  const label = (name) => (severity ? SEVERITIES.find((item) => item.key === name)?.label : name === 'count' ? 'Records' : name);
  const common = (
    <>
      <CartesianGrid strokeDasharray="3 3" stroke="var(--grid)" vertical={false} />
      <XAxis dataKey="label" {...axis} minTickGap={28} />
      <YAxis {...axis} allowDecimals={false} width={44} />
      <Tooltip {...tooltip} cursor={{ stroke: 'var(--faint)' }} />
      {data.series.length > 1 && <Legend wrapperStyle={{ fontSize: 10, color: 'var(--muted)' }} />}
    </>
  );
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        {chart.kind === 'stacked' ? (
          <BarChart data={rows} barCategoryGap={1}>{common}
            {data.series.map((name, index) => <Bar key={name} dataKey={name} name={label(name)} stackId="s" fill={color(name, index)} stroke="var(--panel)" strokeWidth={1} maxBarSize={22} />)}
          </BarChart>
        ) : chart.kind === 'line' ? (
          <LineChart data={rows}>{common}
            {data.series.map((name, index) => <Line key={name} type="monotone" dataKey={name} name={label(name)} stroke={color(name, index)} strokeWidth={2} dot={false} activeDot={{ r: 4 }} />)}
          </LineChart>
        ) : (
          <AreaChart data={rows}>{common}
            {data.series.map((name, index) => <Area key={name} type="monotone" dataKey={name} name={label(name)} stroke={color(name, index)} fill={color(name, index)} fillOpacity={0.18} strokeWidth={2} />)}
          </AreaChart>
        )}
      </ResponsiveContainer>
    </div>
  );
}

/** One chart panel. `result` is the react-query result of /modules/:module/aggregations. */
export function ChartCard({ chart, result, onSelect, height = 220, primary = false, className = '' }) {
  const data = result.data?.charts?.[chart.key];
  return (
    <div className={`panel chart-panel module-chart ${chart.wide ? 'wide' : ''} ${primary ? 'primary-chart' : ''} ${className}`}>
      <PanelTitle title={chart.title} subtitle={chart.note || (primary ? `${fmtNumber(result.data?.total || 0)} matching records` : undefined)} tag={primary ? 'SEARCH ANALYTICS' : undefined} />
      {result.isLoading ? <Loading /> : result.error ? <ErrorState error={result.error} />
        : !data ? <Empty message="No data." />
          : data.type === 'error' ? <ErrorState error={data.message} title="Chart unavailable" hint="" />
            : data.type === 'series' ? <Series chart={chart} data={data} interval={result.data.range?.interval} height={height} />
              : <Categorical chart={chart} data={data} onSelect={onSelect} height={height} />}
    </div>
  );
}

export function KpiRow({ kpis, result, inventory = false }) {
  return (
    <div className="kpi-grid module-kpis" style={{ gridTemplateColumns: `repeat(${Math.min(kpis.length, 5)}, minmax(0, 1fr))` }}>
      {kpis.map((kpi, index) => (
        <div key={kpi.key} className={`kpi-card kpi-${index % 4} tone-${kpi.tone || 'none'}`}>
          <div className="kpi-head"><span>{kpi.label}</span></div>
          <div className="kpi-value">{result.isLoading ? '…' : result.error ? '—' : fmtNumber(result.data?.kpis?.[kpi.key] ?? 0)}</div>
          <div className="kpi-foot"><span>{kpi.share && result.data?.total ? `${(((result.data.kpis?.[kpi.key] || 0) / result.data.total) * 100).toFixed(1)}% of total` : inventory ? 'Current inventory' : 'In selected range'}</span></div>
        </div>
      ))}
    </div>
  );
}
