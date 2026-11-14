import { severityOf } from './severity.js';

const get = (object, path) => path.split('.').reduce((value, key) => (value == null ? undefined : value[key]), object);

// `weight` drives relative column width in PDF output.
export const ALERT_COLUMNS = [
  { key: 'timestamp', label: 'Timestamp', weight: 1.4, value: (e) => e['@timestamp'] || e.timestamp },
  { key: 'severity', label: 'Severity', weight: 0.8, value: (e) => severityOf(e.rule?.level) },
  { key: 'rule.level', label: 'Level', weight: 0.5 },
  { key: 'rule.id', label: 'Rule ID', weight: 0.7 },
  { key: 'rule.description', label: 'Description', weight: 3 },
  { key: 'rule.groups', label: 'Rule groups', weight: 1.6 },
  { key: 'rule.mitre.id', label: 'MITRE technique', weight: 1 },
  { key: 'agent.id', label: 'Agent ID', weight: 0.6 },
  { key: 'agent.name', label: 'Agent', weight: 1.2 },
  { key: 'agent.ip', label: 'Agent IP', weight: 1 },
  { key: 'data.srcip', label: 'Source IP', weight: 1 },
  { key: 'data.dstip', label: 'Destination IP', weight: 1 },
  { key: 'data.srcuser', label: 'Source user', weight: 1 },
  { key: 'data.dstuser', label: 'Destination user', weight: 1 },
  { key: 'location', label: 'Location', weight: 1.4 },
  { key: 'decoder.name', label: 'Decoder', weight: 0.9 },
  { key: 'manager.name', label: 'Manager', weight: 1 },
  { key: 'full_log', label: 'Full log', weight: 4 },
];

export const VULNERABILITY_COLUMNS = [
  { key: 'timestamp', label: 'Detected', weight: 1.4, value: (e) => e['@timestamp'] || e.timestamp },
  { key: 'agent.name', label: 'Agent', weight: 1.2 },
  { key: 'agent.id', label: 'Agent ID', weight: 0.6 },
  { key: 'data.vulnerability.cve', label: 'CVE', weight: 1.1 },
  { key: 'data.vulnerability.severity', label: 'Severity', weight: 0.8 },
  { key: 'data.vulnerability.cvss.cvss3.base_score', label: 'CVSS3', weight: 0.6 },
  { key: 'data.vulnerability.package.name', label: 'Package', weight: 1.4 },
  { key: 'data.vulnerability.package.version', label: 'Version', weight: 1 },
  { key: 'data.vulnerability.status', label: 'Status', weight: 0.8 },
  { key: 'data.vulnerability.title', label: 'Title', weight: 3 },
  { key: 'rule.description', label: 'Rule description', weight: 2.4 },
];

export const AGENT_COLUMNS = [
  { key: 'id', label: 'Agent ID', weight: 0.6 },
  { key: 'name', label: 'Name', weight: 1.4 },
  { key: 'ip', label: 'IP address', weight: 1 },
  { key: 'status', label: 'Status', weight: 0.9 },
  { key: 'os.name', label: 'Operating system', weight: 2 },
  { key: 'os.platform', label: 'Platform', weight: 0.8 },
  { key: 'os.version', label: 'OS version', weight: 1 },
  { key: 'version', label: 'Agent version', weight: 1 },
  { key: 'group', label: 'Groups', weight: 1, value: (a) => (Array.isArray(a.group) ? a.group.join(', ') : a.group) },
  { key: 'node_name', label: 'Node', weight: 0.8 },
  { key: 'registerIP', label: 'Registration IP', weight: 1 },
  { key: 'dateAdd', label: 'Registered', weight: 1.4 },
  { key: 'lastKeepAlive', label: 'Last keep-alive', weight: 1.4 },
];

export function columnValue(column, record) {
  const value = column.value ? column.value(record) : get(record, column.key);
  return Array.isArray(value) ? value.join(', ') : value;
}

const AUTH_GROUPS = ['authentication_success', 'authentication_failed', 'authentication_failures', 'invalid_login', 'win_authentication_failed', 'pam', 'sshd'];
const NETWORK_GROUPS = ['firewall', 'ids', 'suricata', 'snort', 'web', 'accesslog', 'attack', 'iptables', 'pfsense', 'fortigate', 'cisco', 'netscreenfw', 'sonicwall', 'squid', 'proxy', 'connection_attempt', 'recon'];

const SUMMARY_SECTIONS = ['severity', 'timeline', 'top_agents', 'top_rules', 'top_srcips', 'top_dstips'];
const DEFAULT_ALERT_COLUMNS = ['timestamp', 'severity', 'rule.level', 'rule.id', 'rule.description', 'agent.name', 'data.srcip', 'data.dstip'];

/**
 * Report catalog.
 * source: 'alerts' (OpenSearch), 'agents' (Wazuh Manager API).
 * baseFilters: filters always applied; user filters are merged on top.
 * defaultFilters: applied only when the user leaves that filter empty.
 */
export const REPORT_TYPES = {
  daily_security: {
    label: 'Daily Security Report', description: 'Security posture for the previous day with notable (high and critical) alerts.',
    source: 'alerts', defaultPeriod: 'previous_day', sections: SUMMARY_SECTIONS, details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS, defaultFilters: { severity: ['critical', 'high'] },
  },
  weekly_security: {
    label: 'Weekly Security Report', description: 'Seven-day security trends, top sources and notable alerts.',
    source: 'alerts', defaultPeriod: 'previous_week', sections: SUMMARY_SECTIONS, details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS, defaultFilters: { severity: ['critical', 'high'] },
  },
  monthly_security: {
    label: 'Monthly Security Report', description: 'Monthly security trends, top sources and notable alerts.',
    source: 'alerts', defaultPeriod: 'previous_month', sections: SUMMARY_SECTIONS, details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS, defaultFilters: { severity: ['critical', 'high'] },
  },
  critical_alerts: {
    label: 'Critical Alerts Report', description: 'All critical alerts (rule level 15).',
    source: 'alerts', defaultPeriod: 'last_24h', sections: ['timeline', 'top_agents', 'top_rules', 'top_srcips'], details: true,
    columns: ALERT_COLUMNS, defaultColumns: [...DEFAULT_ALERT_COLUMNS, 'full_log'], baseFilters: { severity: ['critical'] },
  },
  high_alerts: {
    label: 'High Severity Alerts Report', description: 'All high severity alerts (rule level 12–14).',
    source: 'alerts', defaultPeriod: 'last_24h', sections: ['timeline', 'top_agents', 'top_rules', 'top_srcips'], details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS, baseFilters: { severity: ['high'] },
  },
  security_events: {
    label: 'Security Events Report', description: 'All security events matching the selected filters.',
    source: 'alerts', defaultPeriod: 'last_24h', sections: SUMMARY_SECTIONS, details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS,
  },
  agent_inventory: {
    label: 'Agent Inventory Report', description: 'Complete Wazuh agent inventory from the Manager API.',
    source: 'agents', periodless: true, sections: ['agent_status', 'agent_platforms'], details: true,
    columns: AGENT_COLUMNS, defaultColumns: ['id', 'name', 'ip', 'status', 'os.name', 'version', 'group', 'lastKeepAlive'],
  },
  agent_status: {
    label: 'Agent Status Report', description: 'Agent connectivity status, disconnected and never-connected agents.',
    source: 'agents', periodless: true, sections: ['agent_status'], details: true,
    columns: AGENT_COLUMNS, defaultColumns: ['id', 'name', 'ip', 'status', 'version', 'lastKeepAlive', 'dateAdd'],
    sortAgents: true,
  },
  authentication_events: {
    label: 'Authentication Events Report', description: 'Successful and failed authentication events.',
    source: 'alerts', defaultPeriod: 'last_24h', sections: ['auth_outcomes', 'timeline', 'top_srcips', 'top_users', 'top_agents'], details: true,
    columns: ALERT_COLUMNS, defaultColumns: ['timestamp', 'severity', 'rule.id', 'rule.description', 'agent.name', 'data.srcip', 'data.srcuser', 'data.dstuser'],
    extraQuery: [{ bool: { should: [{ terms: { 'rule.groups': AUTH_GROUPS } }, { prefix: { 'rule.groups': 'authentication' } }], minimum_should_match: 1 } }],
  },
  network_security: {
    label: 'Network Security Report', description: 'Firewall, IDS, web and other network security events.',
    source: 'alerts', defaultPeriod: 'last_24h', sections: ['severity', 'timeline', 'top_srcips', 'top_dstips', 'top_rules'], details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS,
    extraQuery: [{ bool: { should: [{ terms: { 'rule.groups': NETWORK_GROUPS } }, { exists: { field: 'data.dstip' } }], minimum_should_match: 1 } }],
  },
  vulnerability: {
    label: 'Vulnerability Report', description: 'Vulnerability Detector findings reported by Wazuh agents.',
    source: 'alerts', defaultPeriod: 'last_30d', sections: ['vuln_severity', 'top_cves', 'top_packages', 'top_agents'], details: true,
    columns: VULNERABILITY_COLUMNS,
    defaultColumns: ['timestamp', 'agent.name', 'data.vulnerability.cve', 'data.vulnerability.severity', 'data.vulnerability.cvss.cvss3.base_score', 'data.vulnerability.package.name', 'data.vulnerability.package.version', 'data.vulnerability.status'],
    extraQuery: [{ bool: { should: [{ term: { 'rule.groups': 'vulnerability-detector' } }, { exists: { field: 'data.vulnerability.cve' } }], minimum_should_match: 1 } }],
  },
  rule_distribution: {
    label: 'Rule Distribution Report', description: 'How often each Wazuh rule fired, with affected agents.',
    source: 'alerts', defaultPeriod: 'last_7d', sections: ['severity', 'rule_distribution'], details: false,
  },
  top_attacking_ips: {
    label: 'Top Attacking IPs Report', description: 'Source IP addresses generating the most alerts.',
    source: 'alerts', defaultPeriod: 'last_7d', sections: ['attacking_ips'], details: false,
    extraQuery: [{ exists: { field: 'data.srcip' } }],
  },
  executive_summary: {
    label: 'Executive Security Summary', description: 'High-level overview of alert volume, severity, agents and top threats.',
    source: 'alerts', defaultPeriod: 'previous_week', sections: ['severity', 'timeline', 'agent_status', 'top_rules', 'top_agents', 'top_srcips'], details: false,
    executive: true,
  },
  custom: {
    label: 'Custom Report', description: 'Alerts matching your own filters and selected columns.',
    source: 'alerts', defaultPeriod: 'last_24h', sections: ['severity', 'timeline', 'top_agents', 'top_rules'], details: true,
    columns: ALERT_COLUMNS, defaultColumns: DEFAULT_ALERT_COLUMNS,
  },
};

export const REPORT_TYPE_KEYS = Object.keys(REPORT_TYPES);
export const REPORT_FORMATS = ['pdf', 'xlsx', 'csv'];
export const REPORT_PERIODS = ['last_24h', 'last_7d', 'last_30d', 'previous_day', 'previous_week', 'previous_month'];

/** Public catalog for the UI (no functions). */
export function reportCatalog() {
  return REPORT_TYPE_KEYS.map((key) => {
    const type = REPORT_TYPES[key];
    return {
      key, label: type.label, description: type.description, source: type.source,
      periodless: Boolean(type.periodless), defaultPeriod: type.defaultPeriod || null,
      columns: (type.columns || []).map(({ key: column, label }) => ({ key: column, label })),
      defaultColumns: type.defaultColumns || [],
      lockedFilters: Object.keys(type.baseFilters || {}),
      supportsFilters: type.source === 'alerts',
    };
  });
}
