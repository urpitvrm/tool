import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Copy } from 'lucide-react';
import { api } from '../api.js';
import { Drawer, ErrorState, Segmented, SeverityBadge, StatusPill, useToast } from './common.jsx';
import { fmtDate } from '../lib/format.js';

export const getPath = (record, path) => {
  if (record == null) return undefined;
  if (Object.prototype.hasOwnProperty.call(record, path)) return record[path];
  return path.split('.').reduce((value, part) => (value == null ? undefined : value[part]), record);
};

function DetailRow({ label, value, mono, onFilter }) {
  if (value == null || value === '' || (Array.isArray(value) && !value.length)) return null;
  const text = Array.isArray(value) ? value.join(', ') : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return (
    <div className="detail-row">
      <span>{label}</span>
      <b className={mono ? 'mono' : ''}>{text}</b>
      {onFilter && <button className="text-button" onClick={onFilter} title={`Filter by ${label}`}>filter</button>}
    </div>
  );
}

function CopyJson({ record }) {
  const { notify } = useToast();
  return <button className="secondary wide" onClick={() => navigator.clipboard?.writeText(JSON.stringify(record, null, 2)).then(() => notify('Record JSON copied'))}><Copy size={13} /> Copy raw JSON</button>;
}

/** Wazuh alert / security event. `onFilter(filterKey, value)` adds a Search filter. */
export function AlertDrawer({ alert, onClose, onFilter }) {
  const [tab, setTab] = useState('summary');
  const rule = alert.rule || {};
  const data = alert.data || {};
  const filterBy = (key, value) => (onFilter && value != null && value !== '' ? () => onFilter(key, value) : undefined);
  return (
    <Drawer title={rule.description || 'Security event'} eyebrow="EVENT DETAILS" onClose={onClose} actions={<CopyJson record={alert} />}>
      <div className="drawer-meta"><SeverityBadge level={rule.level} /><code>{alert._id}</code></div>
      <Segmented options={[{ key: 'summary', label: 'Summary' }, { key: 'json', label: 'Raw JSON' }]} value={tab} onChange={setTab} />
      {tab === 'json' ? <pre className="json-view">{JSON.stringify(alert, null, 2)}</pre> : (
        <div className="detail-sections">
          <section><h4>Event</h4>
            <DetailRow label="Timestamp" value={fmtDate(alert['@timestamp'])} />
            <DetailRow label="Event type" value={rule.groups} />
            <DetailRow label="Location" value={alert.location} mono />
            <DetailRow label="Decoder" value={alert.decoder?.name} />
            <DetailRow label="Manager" value={alert.manager?.name} />
          </section>
          <section><h4>Rule</h4>
            <DetailRow label="Rule ID" value={rule.id} mono onFilter={filterBy('rule_id', rule.id)} />
            <DetailRow label="Level" value={rule.level} onFilter={filterBy('level', rule.level)} />
            <DetailRow label="Description" value={rule.description} />
            <DetailRow label="Fired times" value={rule.firedtimes} />
            <DetailRow label="MITRE technique" value={rule.mitre?.id} />
            <DetailRow label="MITRE tactic" value={rule.mitre?.tactic} />
            <DetailRow label="PCI DSS" value={rule.pci_dss} />
            <DetailRow label="GDPR" value={rule.gdpr} />
            <DetailRow label="HIPAA" value={rule.hipaa} />
            <DetailRow label="NIST 800-53" value={rule.nist_800_53} />
          </section>
          <section><h4>Agent</h4>
            <DetailRow label="Name" value={alert.agent?.name} onFilter={filterBy('agent_name', alert.agent?.name)} />
            <DetailRow label="ID" value={alert.agent?.id} mono onFilter={filterBy('agent_id', alert.agent?.id)} />
            <DetailRow label="IP" value={alert.agent?.ip} mono />
          </section>
          {(data.srcip || data.dstip || data.srcuser || data.dstuser || data.protocol) && (
            <section><h4>Network &amp; identity</h4>
              <DetailRow label="Source IP" value={data.srcip} mono onFilter={filterBy('srcip', data.srcip)} />
              <DetailRow label="Source port" value={data.srcport} mono />
              <DetailRow label="Destination IP" value={data.dstip} mono onFilter={filterBy('dstip', data.dstip)} />
              <DetailRow label="Destination port" value={data.dstport} mono />
              <DetailRow label="Protocol" value={data.protocol} />
              <DetailRow label="Source user" value={data.srcuser} />
              <DetailRow label="Destination user" value={data.dstuser} />
            </section>
          )}
          {alert.syscheck && (
            <section><h4>File integrity</h4>
              <DetailRow label="Path" value={alert.syscheck.path} mono />
              <DetailRow label="Change" value={alert.syscheck.event} />
              <DetailRow label="Mode" value={alert.syscheck.mode} />
              <DetailRow label="SHA256 after" value={alert.syscheck.sha256_after} mono />
            </section>
          )}
          {data.sca?.check && (
            <section><h4>Configuration check</h4>
              <DetailRow label="Policy" value={data.sca.policy} />
              <DetailRow label="Check" value={`${data.sca.check.id} · ${data.sca.check.title}`} />
              <DetailRow label="Result" value={data.sca.check.result} />
              <DetailRow label="Rationale" value={data.sca.check.rationale} />
              <DetailRow label="Remediation" value={data.sca.check.remediation} />
            </section>
          )}
          {data.vulnerability && (
            <section><h4>Vulnerability</h4>
              <DetailRow label="CVE" value={data.vulnerability.cve} mono />
              <DetailRow label="Severity" value={data.vulnerability.severity} />
              <DetailRow label="Package" value={`${data.vulnerability.package?.name || ''} ${data.vulnerability.package?.version || ''}`.trim()} />
              <DetailRow label="Title" value={data.vulnerability.title} />
            </section>
          )}
          {alert.full_log && <section><h4>Full log</h4><pre className="json-view compact">{alert.full_log}</pre></section>}
        </div>
      )}
    </Drawer>
  );
}

/** Wazuh agent, refreshed from the Manager API. */
export function AgentDrawer({ agent: initial, onClose, onViewAlerts }) {
  const [tab, setTab] = useState('details');
  const detail = useQuery({ queryKey: ['agent', initial.id], queryFn: () => api.get(`/agents/${initial.id}`).then((r) => r.data), initialData: initial });
  const agent = detail.data || initial;
  const rows = [
    ['Agent ID', agent.id], ['Name', agent.name], ['Status', agent.status], ['IP address', agent.ip], ['Registration IP', agent.registerIP],
    ['Operating system', agent.os?.name], ['OS version', agent.os?.version], ['Platform', agent.os?.platform], ['Architecture', agent.os?.arch],
    ['Agent version', agent.version], ['Groups', (agent.group || []).join(', ')], ['Group config', agent.group_config_status],
    ['Manager', agent.manager], ['Node', agent.node_name], ['Registered', fmtDate(agent.dateAdd)], ['Last keep-alive', fmtDate(agent.lastKeepAlive)],
  ];
  return (
    <Drawer title={agent.name} eyebrow={`AGENT ${agent.id}`} onClose={onClose}
      actions={onViewAlerts && <button className="secondary wide" onClick={() => onViewAlerts(agent)}>View events from this agent</button>}>
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
