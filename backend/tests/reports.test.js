import test from 'node:test';
import assert from 'node:assert/strict';
import { buildAlertQuery } from '../src/utils/opensearch-query.js';
import { REPORT_TYPE_KEYS, REPORT_TYPES, reportCatalog } from '../src/constants/report-types.js';
import { effectiveFilters } from '../src/services/report-data.service.js';
import { renderReport } from '../src/utils/report-renderers/index.js';
import { generateReportSchema, scheduleSchema } from '../src/validators/report.validator.js';
import { eventFilterSchema } from '../src/validators/api.validator.js';
import { isTransientEmailError } from '../src/services/email.service.js';

test('alert query uses Wazuh keyword fields and severity bands', () => {
  const query = buildAlertQuery({ range: { gte: 'a', lte: 'b' }, severity: ['critical', 'high'], agent: ['001', 'web-*'], ruleId: ['5710'], srcip: ['10.0.0.1'], q: 'ssh' });
  const text = JSON.stringify(query);
  assert.ok(!text.includes('.keyword'), 'Wazuh alert fields are keyword-mapped without sub-fields');
  assert.ok(text.includes('"rule.level":{"gte":15}'));
  assert.ok(text.includes('"rule.level":{"gte":12,"lte":14}'));
  assert.ok(text.includes('"agent.id":["001"]'));
  assert.ok(text.includes('"wildcard":{"agent.name"'));
  assert.ok(text.includes('"rule.id":["5710"]'));
  assert.equal(query.bool.must[0].simple_query_string.query, 'ssh');
});

test('all fifteen report types are defined with labels', () => {
  assert.equal(REPORT_TYPE_KEYS.length, 15);
  for (const entry of reportCatalog()) assert.ok(entry.label && entry.description);
});

test('locked report filters cannot be overridden and defaults fill gaps', () => {
  assert.deepEqual(effectiveFilters(REPORT_TYPES.critical_alerts, { severity: ['low'] }).severity, ['critical']);
  assert.deepEqual(effectiveFilters(REPORT_TYPES.daily_security, {}).severity, ['critical', 'high']);
  assert.deepEqual(effectiveFilters(REPORT_TYPES.daily_security, { severity: ['low'] }).severity, ['low']);
});

const sampleDocument = {
  title: 'Unit test report', reportType: 'security_events', reportLabel: 'Security Events Report',
  period: { from: new Date('2026-11-01T00:00:00Z'), to: new Date('2026-11-02T00:00:00Z') },
  generatedAt: new Date('2026-11-02T01:00:00Z'), generatedBy: 'tester', timezone: 'UTC',
  filters: { severity: ['high'] }, kpis: [{ label: 'Total alerts', value: 2 }], notes: [],
  sections: [{ title: 'Top agents', chart: 'bar', labelKey: 'agent', valueKey: 'count', columns: [{ key: 'agent', label: 'Agent' }, { key: 'count', label: 'Alerts' }], rows: [{ agent: 'web-01', count: 2 }] }],
  details: { title: 'Alert details', total: 2, truncated: false, columns: [{ key: 'timestamp', label: 'Timestamp' }, { key: 'rule.description', label: 'Description' }],
    rows: [{ timestamp: '2026-11-01T10:00:00.000Z', 'rule.description': '=HYPERLINK("http://evil")' }, { timestamp: '2026-11-01T11:00:00.000Z', 'rule.description': 'Unicode – “quotes” ✓' }] },
};

test('PDF, XLSX and CSV renderers produce valid files', async () => {
  const pdf = await renderReport(sampleDocument, 'pdf');
  assert.equal(pdf.subarray(0, 4).toString(), '%PDF');
  const xlsx = await renderReport(sampleDocument, 'xlsx');
  assert.equal(xlsx.subarray(0, 2).toString(), 'PK'); // OOXML zip container
  const csv = (await renderReport(sampleDocument, 'csv')).toString('utf8');
  assert.ok(csv.startsWith('﻿"Timestamp","Description"'));
  assert.ok(csv.includes(`"'=HYPERLINK`), 'CSV cells starting with formula characters are neutralized');
});

test('report generation and schedule requests are validated', () => {
  assert.equal(generateReportSchema.safeParse({ name: 'x', report_type: 'custom', format: 'pdf' }).success, true);
  assert.equal(generateReportSchema.safeParse({ name: 'x', report_type: 'custom', format: 'docx' }).success, false);
  assert.equal(generateReportSchema.safeParse({ name: 'x', report_type: 'custom', format: 'pdf', timezone: 'Mars/Base' }).success, false);
  const schedule = { name: 'Daily', report_type: 'daily_security', format: 'pdf', frequency: 'daily', start_date: '2026-11-12', start_time: '07:00', timezone: 'UTC', recipients: ['soc@example.com'], email_subject: 'Daily report' };
  assert.equal(scheduleSchema.safeParse(schedule).success, true);
  assert.equal(scheduleSchema.safeParse({ ...schedule, recipients: [] }).success, false);
  assert.equal(scheduleSchema.safeParse({ ...schedule, recipients: ['not-an-email'] }).success, false);
  assert.equal(scheduleSchema.safeParse({ ...schedule, email_subject: 'x\r\nBcc: a@b.c' }).success, false);
  assert.equal(scheduleSchema.safeParse({ ...schedule, frequency: 'cron' }).success, false);
  assert.equal(scheduleSchema.safeParse({ ...schedule, end_date: '2026-11-01' }).success, false);
});

test('event filters parse comma-separated query parameters', () => {
  const parsed = eventFilterSchema.parse({ severity: 'critical,high', rule_id: '5710,5712', srcip: '10.0.0.*' });
  assert.deepEqual(parsed.severity, ['critical', 'high']);
  assert.deepEqual(parsed.rule_id, ['5710', '5712']);
  assert.equal(eventFilterSchema.safeParse({ severity: 'urgent' }).success, false);
  assert.equal(eventFilterSchema.safeParse({ srcip: '1.2.3.4; DROP' }).success, false);
});

test('only transient SMTP failures are retried', () => {
  assert.equal(isTransientEmailError({ code: 'ETIMEDOUT' }), true);
  assert.equal(isTransientEmailError({ responseCode: 451 }), true);
  assert.equal(isTransientEmailError({ responseCode: 550 }), false);
  assert.equal(isTransientEmailError({ code: 'EAUTH', responseCode: 535 }), false);
});
