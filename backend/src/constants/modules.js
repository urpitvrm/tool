// Declarative definitions for the two-tab (Dashboard / Search) module workspaces.
// One definition drives the KPIs, charts, primary search graph, filters, table columns and exports,
// so every view of a module is built from the same parsed filters.

const AUTH_SUCCESS = ['authentication_success'];
const AUTH_FAILURE = ['authentication_failed', 'authentication_failures', 'invalid_login', 'win_authentication_failed'];

const field = (key, label, options = {}) => ({ key, label, type: 'keyword', sortable: true, ...options });

// ---- Field catalogs (Wazuh 4.x alert template: keyword fields, no `.keyword` sub-fields) ----------
const EVENT_FIELDS = [
  field('@timestamp', 'Timestamp', { type: 'date' }),
  field('rule.id', 'Rule ID'),
  field('rule.level', 'Rule Level', { type: 'number' }),
  field('rule.description', 'Rule Description'),
  field('agent.id', 'Agent ID'),
  field('agent.name', 'Agent Name'),
  field('agent.ip', 'Agent IP'),
  field('data.srcip', 'Source IP'),
  field('data.dstip', 'Destination IP'),
  field('rule.groups', 'Event Type'),
  field('data.protocol', 'Protocol'),
  field('data.srcport', 'Source Port'),
  field('data.dstport', 'Destination Port'),
  field('data.srcuser', 'Source User'),
  field('data.dstuser', 'Destination User'),
  field('rule.mitre.id', 'MITRE Technique ID'),
  field('rule.mitre.tactic', 'MITRE Tactic'),
  field('decoder.name', 'Decoder'),
  field('location', 'Location'),
  field('manager.name', 'Manager'),
  field('rule.firedtimes', 'Fired Times', { type: 'number' }),
  field('full_log', 'Full Log', { type: 'text', sortable: false }),
];
const pick = (keys, extra = []) => [...keys.map((key) => EVENT_FIELDS.find((item) => item.key === key)), ...extra];

const EVENT_DEFAULT_COLUMNS = ['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.id', 'agent.name', 'agent.ip', 'data.srcip', 'data.dstip', 'rule.groups'];

// ---- Reusable filters -------------------------------------------------------------------------
// type: list (comma-separated, `*` wildcards) | levelRange | multi (fixed options) | contains
const F = {
  level: { key: 'level', label: 'Rule Level', type: 'levelRange', field: 'rule.level', min: 0, max: 15 },
  ruleId: { key: 'rule_id', label: 'Rule ID', type: 'list', field: 'rule.id', placeholder: '5710, 5712', pattern: '^\\d{1,10}$' },
  agentId: { key: 'agent_id', label: 'Agent ID', type: 'list', field: 'agent.id', placeholder: '001, 002', pattern: '^\\d{1,8}$' },
  agentName: { key: 'agent_name', label: 'Agent Name', type: 'list', field: 'agent.name', placeholder: 'web-01, db-*' },
  srcip: { key: 'srcip', label: 'Source IP', type: 'list', field: 'data.srcip', placeholder: '192.168.1.10, 10.0.*', pattern: '^[0-9a-fA-F:.*]{1,64}$' },
  dstip: { key: 'dstip', label: 'Destination IP', type: 'list', field: 'data.dstip', placeholder: '10.0.0.5', pattern: '^[0-9a-fA-F:.*]{1,64}$' },
  eventType: { key: 'event_type', label: 'Event Type', type: 'list', field: 'rule.groups', placeholder: 'sshd, syscheck, web', suggest: 'rule.groups' },
  protocol: { key: 'protocol', label: 'Protocol', type: 'list', field: 'data.protocol', placeholder: 'tcp, udp', suggest: 'data.protocol' },
  severity: {
    key: 'severity', label: 'Severity', type: 'multi', field: 'rule.level',
    options: [
      { key: 'critical', label: 'Critical (15+)', range: { gte: 15 } },
      { key: 'high', label: 'High (12–14)', range: { gte: 12, lte: 14 } },
      { key: 'medium', label: 'Medium (7–11)', range: { gte: 7, lte: 11 } },
      { key: 'low', label: 'Low (0–6)', range: { gte: 0, lte: 6 } },
    ],
  },
  mitreTactic: { key: 'mitre_tactic', label: 'MITRE Tactic', type: 'list', field: 'rule.mitre.tactic', placeholder: 'Persistence', suggest: 'rule.mitre.tactic' },
  mitreTechnique: { key: 'mitre_id', label: 'MITRE Technique ID', type: 'list', field: 'rule.mitre.id', placeholder: 'T1078' },
};
const EVENT_FILTERS = [F.level, F.ruleId, F.agentId, F.agentName, F.srcip, F.dstip, F.eventType, F.protocol];

// ---- KPI and chart helpers ------------------------------------------------------------------------
const SEVERITY_KPIS = [
  { key: 'critical', label: 'Critical', type: 'severity', band: 'critical', tone: 'critical' },
  { key: 'high', label: 'High Severity', type: 'severity', band: 'high', tone: 'high' },
  { key: 'medium', label: 'Medium Severity', type: 'severity', band: 'medium', tone: 'medium' },
  { key: 'low', label: 'Low Severity', type: 'severity', band: 'low', tone: 'low' },
];
const chart = (key, title, kind, agg, options = {}) => ({ key, title, kind, agg, ...options });
const terms = (fieldName, size = 10) => ({ type: 'terms', field: fieldName, size });

const levelChart = (title = 'Events by rule level') => chart('by_level', title, 'bar', { type: 'level' }, { xLabel: 'Rule Level', yLabel: 'Events', colorBy: 'level' });
const severityChart = (title) => chart('by_severity', title, 'donut', { type: 'severity' }, { colorBy: 'severity' });
const timeline = (title, kind = 'area') => chart('over_time', title, kind, { type: 'timeline' }, { wide: true });
const severityTimeline = (title) => chart('severity_over_time', title, 'stacked', { type: 'severity_timeline' }, { wide: true, colorBy: 'severity' });

// ---- Modules --------------------------------------------------------------------------------------
const alertModule = (overrides) => ({
  source: 'opensearch',
  fields: EVENT_FIELDS,
  defaultColumns: EVENT_DEFAULT_COLUMNS,
  defaultSort: { field: '@timestamp', order: 'desc' },
  filters: EVENT_FILTERS,
  kpis: [{ key: 'total', label: 'Total Events', type: 'total' }, ...SEVERITY_KPIS],
  ...overrides,
});

const FRAMEWORKS = {
  pci_dss: ['PCI DSS', 'rule.pci_dss', '/compliance/pci-dss'],
  nist_800_53: ['NIST 800-53', 'rule.nist_800_53', '/compliance/nist-800-53'],
  gdpr: ['GDPR', 'rule.gdpr', '/compliance/gdpr'],
  hipaa: ['HIPAA', 'rule.hipaa', '/compliance/hipaa'],
  cis_controls: ['CIS Controls v8', 'rule.cis_csc_v8', '/compliance/cis-controls'],
  iso_27001: ['ISO 27001', 'rule.iso_27001-2013', '/compliance/iso-27001'],
};

function frameworkModule(key, [label, controlField, path]) {
  return alertModule({
    key, label, path, category: 'Compliance',
    description: `Alerts mapped to ${label} controls by Wazuh rules.`,
    baseQuery: [{ exists: { field: controlField } }],
    fields: [field('@timestamp', 'Timestamp', { type: 'date' }), field(controlField, `${label} Control`), ...EVENT_FIELDS.slice(1)],
    defaultColumns: ['@timestamp', controlField, 'rule.id', 'rule.level', 'rule.description', 'agent.id', 'agent.name', 'rule.groups'],
    filters: [{ key: 'control', label: `${label} Control`, type: 'list', field: controlField, placeholder: 'e.g. 10.2.5', suggest: controlField }, F.level, F.ruleId, F.agentId, F.agentName, F.eventType],
    kpis: [
      { key: 'total', label: 'Mapped Alerts', type: 'total' },
      { key: 'controls', label: 'Controls Triggered', type: 'cardinality', field: controlField },
      { key: 'agents', label: 'Agents Affected', type: 'cardinality', field: 'agent.id' },
      SEVERITY_KPIS[1], SEVERITY_KPIS[2],
    ],
    dashboardCharts: [
      timeline('Alerts over time'),
      chart('by_control', `Alerts by ${label} control`, 'hbar', terms(controlField, 15)),
      severityChart('Alerts by severity'),
      chart('by_agent', 'Alerts by agent', 'hbar', terms('agent.name')),
      chart('by_rule', 'Top rules', 'hbar', { type: 'rule' }),
    ],
    primaryChart: chart('primary', `Alert distribution by ${label} control`, 'bar', terms(controlField, 30), { xLabel: `${label} Control`, yLabel: 'Alerts' }),
    searchCharts: [timeline('Logs over time')],
  });
}

const SCA_FIELDS = [
  field('@timestamp', 'Timestamp', { type: 'date' }),
  field('agent.id', 'Agent ID'), field('agent.name', 'Agent Name'),
  field('data.sca.policy', 'Policy'), field('data.sca.check.id', 'Check ID'), field('data.sca.check.title', 'Check'),
  field('data.sca.check.result', 'Result'), field('data.sca.check.previous_result', 'Previous Result'),
  field('data.sca.check.compliance.cis', 'CIS'), field('data.sca.check.compliance.pci_dss', 'PCI DSS'),
  field('data.sca.check.compliance.nist_800_53', 'NIST 800-53'), field('data.sca.check.compliance.hipaa', 'HIPAA'),
  field('data.sca.check.rationale', 'Rationale', { sortable: false }), field('data.sca.check.remediation', 'Remediation', { sortable: false }),
  field('rule.id', 'Rule ID'), field('rule.level', 'Rule Level', { type: 'number' }),
];
const SCA_FILTERS = [
  { key: 'result', label: 'Control Status', type: 'multi', field: 'data.sca.check.result', options: [{ key: 'passed', label: 'Passed' }, { key: 'failed', label: 'Failed' }, { key: 'not applicable', label: 'Not applicable' }] },
  { key: 'policy', label: 'Policy', type: 'list', field: 'data.sca.policy', suggest: 'data.sca.policy', placeholder: 'CIS Microsoft Windows 11…' },
  { key: 'check_id', label: 'Check ID', type: 'list', field: 'data.sca.check.id', placeholder: '26000' },
  F.agentId, F.agentName,
];
const scaModule = (key, label, path, description, extraBase = []) => ({
  key, label, path, source: 'opensearch', category: key === 'compliance' ? 'Compliance' : 'Threat Detection', description,
  baseQuery: [{ exists: { field: 'data.sca.check.result' } }, ...extraBase],
  fields: SCA_FIELDS,
  defaultColumns: ['@timestamp', 'agent.name', 'data.sca.policy', 'data.sca.check.id', 'data.sca.check.title', 'data.sca.check.result', 'data.sca.check.compliance.cis'],
  defaultSort: { field: '@timestamp', order: 'desc' },
  filters: SCA_FILTERS,
  kpis: [
    { key: 'total', label: 'Control Evaluations', type: 'total' },
    { key: 'passed', label: 'Passed', type: 'terms_value', field: 'data.sca.check.result', value: 'passed', tone: 'low' },
    { key: 'failed', label: 'Failed', type: 'terms_value', field: 'data.sca.check.result', value: 'failed', tone: 'critical' },
    { key: 'na', label: 'Not Applicable', type: 'terms_value', field: 'data.sca.check.result', value: 'not applicable', tone: 'medium' },
    { key: 'checks', label: 'Distinct Checks', type: 'cardinality', field: 'data.sca.check.id' },
  ],
  dashboardCharts: [
    chart('by_result', 'Control status distribution', 'donut', terms('data.sca.check.result', 5), { colorBy: 'status' }),
    chart('by_policy', 'Evaluations by policy', 'hbar', terms('data.sca.policy', 8)),
    timeline('Evaluations over time'),
    chart('failed_checks', 'Most frequent failed checks', 'hbar', terms('data.sca.check.title', 10), { filter: { term: { 'data.sca.check.result': 'failed' } } }),
    chart('by_agent', 'Evaluations by agent', 'bar', terms('agent.name')),
  ],
  primaryChart: chart('primary', 'Control status distribution', 'bar', terms('data.sca.check.result', 5), { xLabel: 'Control Status', yLabel: 'Checks', colorBy: 'status' }),
  searchCharts: [timeline('Logs over time')],
});

const AGENT_FIELDS = [
  field('id', 'Agent ID'), field('name', 'Name'), field('ip', 'IP Address'), field('status', 'Status'),
  field('os.name', 'Operating System'), field('os.platform', 'Platform'), field('os.version', 'OS Version'), field('os.arch', 'Architecture'),
  field('version', 'Agent Version'), field('group', 'Groups'), field('node_name', 'Node'), field('manager', 'Manager'),
  field('registerIP', 'Registration IP'), field('dateAdd', 'Registered', { type: 'date' }), field('lastKeepAlive', 'Last Keep-alive', { type: 'date' }),
  field('group_config_status', 'Group Config'), field('status_code', 'Status Code', { type: 'number', sortable: false }),
];

export const MODULES = {
  events: alertModule({
    key: 'events', label: 'Security Events', path: '/events', category: 'Security Operations',
    description: 'All indexed Wazuh security events.',
    dashboardCharts: [
      timeline('Events over time'),
      severityChart('Events by severity'),
      chart('by_rule', 'Events by rule ID', 'hbar', { type: 'rule' }),
      chart('by_agent', 'Events by agent', 'hbar', terms('agent.name')),
      chart('by_category', 'Events by event category', 'pie', terms('rule.groups', 10)),
      chart('top_srcips', 'Top source IPs', 'bar', terms('data.srcip')),
      chart('top_dstips', 'Top destination IPs', 'bar', terms('data.dstip')),
      levelChart(),
    ],
    primaryChart: chart('primary', 'Events by rule level', 'bar', { type: 'level' }, { xLabel: 'Rule Level', yLabel: 'Number of Events', colorBy: 'level' }),
    searchCharts: [timeline('Logs over time')],
  }),
  alerts: alertModule({
    key: 'alerts', label: 'Alerts', path: '/alerts', category: 'Security Operations',
    description: 'Wazuh alerts grouped by severity band.',
    defaultColumns: ['@timestamp', 'rule.level', 'rule.id', 'rule.description', 'agent.name', 'data.srcip', 'data.dstip', 'rule.mitre.tactic', 'rule.groups'],
    filters: [F.severity, F.level, F.ruleId, F.agentId, F.agentName, F.srcip, F.dstip, F.eventType, F.mitreTactic],
    kpis: [{ key: 'total', label: 'Total Alerts', type: 'total' }, ...SEVERITY_KPIS],
    dashboardCharts: [
      severityTimeline('Alerts over time'),
      severityChart('Alerts by severity'),
      chart('by_agent', 'Alerts by agent', 'hbar', terms('agent.name')),
      chart('by_rule', 'Alerts by rule', 'hbar', { type: 'rule' }),
      chart('top_srcips', 'Top alert-generating IPs', 'bar', terms('data.srcip')),
      chart('by_tactic', 'Alerts by MITRE tactic', 'pie', terms('rule.mitre.tactic', 10)),
    ],
    primaryChart: chart('primary', 'Alert severity distribution', 'bar', { type: 'severity' }, { xLabel: 'Severity', yLabel: 'Alerts', colorBy: 'severity' }),
    searchCharts: [timeline('Logs over time')],
  }),
  agents: {
    key: 'agents', label: 'Agents', path: '/agents', category: 'Infrastructure', source: 'wazuh',
    description: 'Agent inventory from the Wazuh Manager API.',
    fields: AGENT_FIELDS,
    defaultColumns: ['id', 'name', 'ip', 'os.name', 'version', 'group', 'status', 'lastKeepAlive'],
    defaultSort: { field: 'id', order: 'asc' },
    filters: [
      { key: 'status', label: 'Status', type: 'multi', field: 'status', options: [{ key: 'active', label: 'Active' }, { key: 'disconnected', label: 'Disconnected' }, { key: 'never_connected', label: 'Never connected' }, { key: 'pending', label: 'Pending' }] },
      { key: 'name', label: 'Agent Name', type: 'contains', field: 'name', placeholder: 'web' },
      { key: 'agent_id', label: 'Agent ID', type: 'list', field: 'id', placeholder: '001, 002', pattern: '^\\d{1,8}$' },
      { key: 'ip', label: 'IP Address', type: 'contains', field: 'ip', placeholder: '192.168.' },
      { key: 'platform', label: 'Platform', type: 'list', field: 'os.platform', placeholder: 'windows, ubuntu', suggest: 'os.platform' },
      { key: 'os', label: 'Operating System', type: 'contains', field: 'os.name', placeholder: 'Windows 11' },
      { key: 'group', label: 'Group', type: 'list', field: 'group', placeholder: 'default', suggest: 'group' },
      { key: 'version', label: 'Agent Version', type: 'contains', field: 'version', placeholder: '4.14' },
    ],
    kpis: [
      { key: 'total', label: 'Total Agents', type: 'total' },
      { key: 'active', label: 'Active', type: 'status', value: 'active', tone: 'low' },
      { key: 'disconnected', label: 'Disconnected', type: 'status', value: 'disconnected', tone: 'critical' },
      { key: 'never_connected', label: 'Never Connected', type: 'status', value: 'never_connected', tone: 'medium' },
      { key: 'pending', label: 'Pending', type: 'status', value: 'pending' },
    ],
    dashboardCharts: [
      chart('by_status', 'Agent status distribution', 'donut', { type: 'distinct', field: 'status' }, { colorBy: 'status' }),
      chart('by_platform', 'Operating system distribution', 'pie', { type: 'distinct', field: 'os.platform' }),
      chart('by_os', 'Operating systems', 'hbar', { type: 'distinct', field: 'os.name' }),
      chart('by_group', 'Agent group distribution', 'hbar', { type: 'distinct', field: 'group' }),
      chart('by_version', 'Agent versions', 'bar', { type: 'distinct', field: 'version' }),
      chart('connection_trend', 'Agent connection events over time', 'line', { type: 'connection_trend' }, { wide: true, note: 'From Wazuh agent start/stop/disconnect alerts in OpenSearch' }),
    ],
    primaryChart: chart('primary', 'Agent status distribution', 'bar', { type: 'distinct', field: 'status' }, { xLabel: 'Status', yLabel: 'Agents', colorBy: 'status' }),
    searchCharts: [chart('by_platform', 'Matching agents by platform', 'donut', { type: 'distinct', field: 'os.platform' })],
  },
  vulnerabilities: alertModule({
    key: 'vulnerabilities', label: 'Vulnerability Detection', path: '/vulnerabilities', category: 'Threat Detection',
    description: 'Vulnerability Detector findings reported in Wazuh alerts.',
    baseQuery: [{ bool: { should: [{ term: { 'rule.groups': 'vulnerability-detector' } }, { exists: { field: 'data.vulnerability.cve' } }], minimum_should_match: 1 } }],
    fields: [
      field('@timestamp', 'Detected', { type: 'date' }), field('agent.id', 'Agent ID'), field('agent.name', 'Agent Name'),
      field('data.vulnerability.cve', 'CVE'), field('data.vulnerability.severity', 'Severity'),
      field('data.vulnerability.cvss.cvss3.base_score', 'CVSS3 Score'), field('data.vulnerability.package.name', 'Package'),
      field('data.vulnerability.package.version', 'Package Version'), field('data.vulnerability.status', 'Status'),
      field('data.vulnerability.title', 'Title'), field('data.vulnerability.published', 'Published', { type: 'date' }),
      field('rule.id', 'Rule ID'), field('rule.level', 'Rule Level', { type: 'number' }),
    ],
    defaultColumns: ['@timestamp', 'agent.name', 'data.vulnerability.cve', 'data.vulnerability.severity', 'data.vulnerability.cvss.cvss3.base_score', 'data.vulnerability.package.name', 'data.vulnerability.package.version', 'data.vulnerability.status'],
    filters: [
      { key: 'vuln_severity', label: 'Vulnerability Severity', type: 'multi', field: 'data.vulnerability.severity', options: ['Critical', 'High', 'Medium', 'Low'].map((value) => ({ key: value, label: value })) },
      { key: 'cve', label: 'CVE', type: 'list', field: 'data.vulnerability.cve', placeholder: 'CVE-2024-*' },
      { key: 'package', label: 'Package', type: 'list', field: 'data.vulnerability.package.name', placeholder: 'openssl' },
      F.agentId, F.agentName,
    ],
    kpis: [
      { key: 'total', label: 'Findings', type: 'total' },
      ...['Critical', 'High', 'Medium', 'Low'].map((value) => ({ key: value.toLowerCase(), label: value, type: 'terms_value', field: 'data.vulnerability.severity', value, tone: value.toLowerCase() })),
      { key: 'cves', label: 'Distinct CVEs', type: 'cardinality', field: 'data.vulnerability.cve' },
    ],
    dashboardCharts: [
      chart('by_vuln_severity', 'Findings by severity', 'donut', terms('data.vulnerability.severity', 5), { colorBy: 'vulnSeverity' }),
      timeline('Findings over time'),
      chart('top_cves', 'Most frequent CVEs', 'hbar', terms('data.vulnerability.cve', 10)),
      chart('top_packages', 'Most affected packages', 'hbar', terms('data.vulnerability.package.name', 10)),
      chart('by_agent', 'Findings by agent', 'bar', terms('agent.name')),
    ],
    primaryChart: chart('primary', 'Vulnerability severity distribution', 'bar', terms('data.vulnerability.severity', 5), { xLabel: 'Severity', yLabel: 'Findings', colorBy: 'vulnSeverity' }),
    searchCharts: [timeline('Logs over time')],
  }),
  compliance: scaModule('compliance', 'Compliance Overview', '/compliance', 'Configuration controls evaluated by Wazuh Security Configuration Assessment, with their status.', [{ exists: { field: 'data.sca.check.compliance.cis' } }]),
  sca: scaModule('sca', 'Security Configuration Assessment', '/sca', 'Results of Wazuh SCA policy checks.'),
  fim: alertModule({
    key: 'fim', label: 'File Integrity Monitoring', path: '/fim', category: 'Threat Detection',
    description: 'File and registry changes detected by Wazuh syscheck.',
    baseQuery: [{ term: { 'rule.groups': 'syscheck' } }],
    fields: [
      field('@timestamp', 'Timestamp', { type: 'date' }), field('agent.id', 'Agent ID'), field('agent.name', 'Agent Name'),
      field('syscheck.path', 'Path'), field('syscheck.event', 'Change'), field('syscheck.mode', 'Mode'),
      field('syscheck.size_after', 'Size After'), field('syscheck.uname_after', 'Owner'), field('syscheck.md5_after', 'MD5 After'),
      field('syscheck.sha256_after', 'SHA256 After'), ...pick(['rule.id', 'rule.level', 'rule.description']),
    ],
    defaultColumns: ['@timestamp', 'agent.name', 'syscheck.path', 'syscheck.event', 'rule.id', 'rule.level', 'rule.description'],
    filters: [
      { key: 'change', label: 'Change Type', type: 'multi', field: 'syscheck.event', options: [{ key: 'added', label: 'Added' }, { key: 'modified', label: 'Modified' }, { key: 'deleted', label: 'Deleted' }] },
      { key: 'path', label: 'Path', type: 'list', field: 'syscheck.path', placeholder: '/etc/*, C:\\Windows\\*' },
      F.level, F.ruleId, F.agentId, F.agentName,
    ],
    kpis: [
      { key: 'total', label: 'File Changes', type: 'total' },
      { key: 'added', label: 'Added', type: 'terms_value', field: 'syscheck.event', value: 'added', tone: 'low' },
      { key: 'modified', label: 'Modified', type: 'terms_value', field: 'syscheck.event', value: 'modified', tone: 'medium' },
      { key: 'deleted', label: 'Deleted', type: 'terms_value', field: 'syscheck.event', value: 'deleted', tone: 'critical' },
      { key: 'paths', label: 'Distinct Paths', type: 'cardinality', field: 'syscheck.path' },
    ],
    dashboardCharts: [
      timeline('File changes over time'),
      chart('by_change', 'Changes by type', 'donut', terms('syscheck.event', 5)),
      chart('top_paths', 'Most changed paths', 'hbar', terms('syscheck.path', 10)),
      chart('by_agent', 'Changes by agent', 'bar', terms('agent.name')),
      chart('by_rule', 'Changes by rule', 'hbar', { type: 'rule' }),
    ],
    primaryChart: chart('primary', 'File changes by type', 'bar', terms('syscheck.event', 5), { xLabel: 'Change Type', yLabel: 'Events' }),
    searchCharts: [timeline('Logs over time')],
  }),
  authentication: alertModule({
    key: 'authentication', label: 'Authentication Monitoring', path: '/authentication-monitoring', category: 'Threat Detection',
    description: 'Successful and failed authentication events.',
    baseQuery: [{ bool: { should: [{ terms: { 'rule.groups': [...AUTH_SUCCESS, ...AUTH_FAILURE, 'pam', 'sshd'] } }, { prefix: { 'rule.groups': 'authentication' } }], minimum_should_match: 1 } }],
    fields: pick(['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.id', 'agent.name', 'data.srcip', 'data.srcuser', 'data.dstuser', 'rule.groups', 'decoder.name', 'location', 'full_log']),
    defaultColumns: ['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.name', 'data.srcip', 'data.srcuser', 'data.dstuser'],
    filters: [
      { key: 'outcome', label: 'Outcome', type: 'multi', field: 'rule.groups', options: [{ key: 'success', label: 'Successful', terms: AUTH_SUCCESS }, { key: 'failure', label: 'Failed', terms: AUTH_FAILURE }] },
      { key: 'user', label: 'User', type: 'list', fields: ['data.srcuser', 'data.dstuser'], placeholder: 'root, admin' },
      F.srcip, F.agentId, F.agentName, F.ruleId, F.level,
    ],
    kpis: [
      { key: 'total', label: 'Authentication Events', type: 'total' },
      { key: 'success', label: 'Successful', type: 'clause', clause: { terms: { 'rule.groups': AUTH_SUCCESS } }, tone: 'low' },
      { key: 'failure', label: 'Failed', type: 'clause', clause: { terms: { 'rule.groups': AUTH_FAILURE } }, tone: 'critical' },
      { key: 'users', label: 'Distinct Users', type: 'cardinality', field: 'data.dstuser' },
      { key: 'sources', label: 'Distinct Source IPs', type: 'cardinality', field: 'data.srcip' },
    ],
    dashboardCharts: [
      chart('outcome', 'Authentication outcomes', 'donut', { type: 'filters', buckets: { Successful: { terms: { 'rule.groups': AUTH_SUCCESS } }, Failed: { terms: { 'rule.groups': AUTH_FAILURE } } } }, { colorBy: 'outcome' }),
      timeline('Authentication events over time'),
      chart('top_users', 'Top target users', 'hbar', terms('data.dstuser')),
      chart('top_srcips', 'Top source IPs', 'bar', terms('data.srcip')),
      chart('by_agent', 'Events by agent', 'hbar', terms('agent.name')),
      chart('by_rule', 'Events by rule', 'hbar', { type: 'rule' }),
    ],
    primaryChart: chart('primary', 'Authentication outcome distribution', 'bar', { type: 'filters', buckets: { Successful: { terms: { 'rule.groups': AUTH_SUCCESS } }, Failed: { terms: { 'rule.groups': AUTH_FAILURE } } } }, { xLabel: 'Outcome', yLabel: 'Events', colorBy: 'outcome' }),
    searchCharts: [timeline('Logs over time')],
  }),
  mitre: alertModule({
    key: 'mitre', label: 'MITRE ATT&CK', path: '/mitre', category: 'Threat Detection',
    description: 'Alerts mapped to MITRE ATT&CK tactics and techniques.',
    baseQuery: [{ exists: { field: 'rule.mitre.id' } }],
    defaultColumns: ['@timestamp', 'rule.mitre.tactic', 'rule.mitre.id', 'rule.id', 'rule.level', 'rule.description', 'agent.name'],
    filters: [F.mitreTactic, F.mitreTechnique, F.level, F.ruleId, F.agentId, F.agentName],
    kpis: [
      { key: 'total', label: 'Mapped Alerts', type: 'total' },
      { key: 'tactics', label: 'Tactics', type: 'cardinality', field: 'rule.mitre.tactic' },
      { key: 'techniques', label: 'Techniques', type: 'cardinality', field: 'rule.mitre.id' },
      SEVERITY_KPIS[1], SEVERITY_KPIS[2],
    ],
    dashboardCharts: [
      chart('by_tactic', 'Alerts by tactic', 'hbar', terms('rule.mitre.tactic', 14)),
      chart('by_technique', 'Top techniques', 'hbar', terms('rule.mitre.technique', 10)),
      timeline('Mapped alerts over time'),
      chart('by_agent', 'Alerts by agent', 'bar', terms('agent.name')),
      severityChart('Alerts by severity'),
    ],
    primaryChart: chart('primary', 'Alert distribution by tactic', 'bar', terms('rule.mitre.tactic', 14), { xLabel: 'Tactic', yLabel: 'Alerts' }),
    searchCharts: [timeline('Logs over time')],
  }),
  rootcheck: alertModule({
    key: 'rootcheck', label: 'Rootcheck', path: '/rootcheck', category: 'Threat Detection',
    description: 'Policy and rootkit checks reported by Wazuh rootcheck.',
    baseQuery: [{ term: { 'rule.groups': 'rootcheck' } }],
    dashboardCharts: [timeline('Rootcheck events over time'), chart('by_rule', 'Events by rule', 'hbar', { type: 'rule' }), chart('by_agent', 'Events by agent', 'hbar', terms('agent.name')), severityChart('Events by severity')],
    primaryChart: levelChart(),
    searchCharts: [timeline('Logs over time')],
  }),
  malware: alertModule({
    key: 'malware', label: 'Malware Detection', path: '/malware', category: 'Threat Detection',
    description: 'Malware detections from VirusTotal, YARA, ClamAV and related integrations.',
    baseQuery: [{ terms: { 'rule.groups': ['virustotal', 'yara', 'malware', 'clamd', 'trojan', 'virus'] } }],
    dashboardCharts: [timeline('Detections over time'), severityChart('Detections by severity'), chart('by_rule', 'Detections by rule', 'hbar', { type: 'rule' }), chart('by_agent', 'Detections by agent', 'hbar', terms('agent.name'))],
    primaryChart: levelChart('Detections by rule level'),
    searchCharts: [timeline('Logs over time')],
  }),
  ...Object.fromEntries(Object.entries(FRAMEWORKS).map(([key, value]) => [key, frameworkModule(key, value)])),
};

/** Public definition for the UI (no OpenSearch clauses). */
export function publicModule(module) {
  const strip = ({ agg, filter: _filter, ...rest }) => ({ ...rest, aggType: agg.type, aggField: agg.field || null });
  return {
    key: module.key, label: module.label, path: module.path, category: module.category, description: module.description, source: module.source,
    fields: module.fields, defaultColumns: module.defaultColumns, defaultSort: module.defaultSort,
    filters: module.filters.map(({ options, ...rest }) => ({ ...rest, ...(options ? { options: options.map(({ key, label }) => ({ key, label })) } : {}) })),
    kpis: module.kpis.map(({ key, label, tone, type }) => ({ key, label, tone, share: !['total', 'cardinality'].includes(type) })),
    dashboardCharts: module.dashboardCharts.map(strip),
    primaryChart: strip(module.primaryChart),
    searchCharts: (module.searchCharts || []).map(strip),
  };
}
