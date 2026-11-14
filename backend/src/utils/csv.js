export function csvCell(value) {
  let text = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export const eventCsvHeader = [
  'timestamp', 'severity', 'rule_id', 'rule_description', 'agent_name',
  'source_ip', 'destination_ip', 'event', 'event_json',
].map(csvCell).join(',');

export function eventCsvRow(event) {
  const rule = event?.rule || {};
  const agent = event?.agent || {};
  const data = event?.data || {};
  const message = event?.full_log || event?.message || rule.description || event?.decoder?.name || '';
  return [
    event?.['@timestamp'] || event?.timestamp,
    rule.level ?? event?.level,
    rule.id,
    rule.description,
    agent.name || agent.id,
    data.srcip,
    data.dstip,
    message,
    event,
  ].map(csvCell).join(',');
}
