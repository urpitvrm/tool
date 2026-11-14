import test from 'node:test';
import assert from 'node:assert/strict';
import { MODULES, publicModule } from '../src/constants/modules.js';
import { agentQueryParams, parseModuleQuery } from '../src/services/module.service.js';

const events = MODULES.events;

test('every module defines KPIs, dashboard charts, a primary search chart and default columns from its catalog', () => {
  for (const module of Object.values(MODULES)) {
    assert.ok(module.kpis.length, `${module.key} kpis`);
    assert.ok(module.dashboardCharts.length >= 3, `${module.key} dashboard charts`);
    assert.ok(module.primaryChart, `${module.key} primary chart`);
    const keys = new Set(module.fields.map((field) => field.key));
    for (const column of module.defaultColumns) assert.ok(keys.has(column), `${module.key} default column ${column}`);
    assert.ok(keys.has(module.defaultSort.field), `${module.key} default sort`);
    const definition = publicModule(module);
    assert.ok(!JSON.stringify(definition).includes('"bool"'), `${module.key} public definition leaks query clauses`);
  }
});

test('security events search bar graph is rule level distribution', () => {
  assert.equal(events.primaryChart.agg.type, 'level');
  assert.equal(events.primaryChart.xLabel, 'Rule Level');
  assert.deepEqual(events.defaultColumns, ['@timestamp', 'rule.id', 'rule.level', 'rule.description', 'agent.id', 'agent.name', 'agent.ip', 'data.srcip', 'data.dstip', 'rule.groups']);
  assert.deepEqual(events.filters.map((filter) => filter.key), ['level', 'rule_id', 'agent_id', 'agent_name', 'srcip', 'dstip', 'event_type', 'protocol']);
});

test('filters combine into one OpenSearch query', () => {
  const parsed = parseModuleQuery(events, {
    minutes: '1440', level_min: '12', level_max: '15', agent_name: 'server-01', srcip: '192.168.1.10', event_type: 'sshd,web*', q: 'failed',
  });
  const text = JSON.stringify(parsed.query);
  assert.ok(text.includes('"rule.level":{"gte":12,"lte":15}'));
  assert.ok(text.includes('"agent.name":["server-01"]'));
  assert.ok(text.includes('"data.srcip":["192.168.1.10"]'));
  assert.ok(text.includes('"rule.groups":["sshd"]') && text.includes('"value":"web*"'));
  assert.equal(parsed.query.bool.must[0].simple_query_string.query, 'failed');
});

test('advanced mode uses query_string; invalid filters are rejected', () => {
  const parsed = parseModuleQuery(events, { q: 'rule.level:>=10 AND agent.name:web*', mode: 'advanced' });
  assert.equal(parsed.query.bool.must[0].query_string.query, 'rule.level:>=10 AND agent.name:web*');
  assert.throws(() => parseModuleQuery(events, { level_min: '20' }), /between 0 and 15/);
  assert.throws(() => parseModuleQuery(events, { level_min: '9', level_max: '3' }), /greater than maximum/);
  assert.throws(() => parseModuleQuery(events, { rule_id: '57x' }), /invalid value/);
  assert.throws(() => parseModuleQuery(MODULES.alerts, { severity: 'urgent' }), /unknown value/);
});

test('module base filters are always applied', () => {
  const text = JSON.stringify(parseModuleQuery(MODULES.fim, {}).query);
  assert.ok(text.includes('"rule.groups":"syscheck"'));
});

test('agent filters become a single Wazuh query shared by list and distinct calls', () => {
  const agents = MODULES.agents;
  const params = agentQueryParams(agents, parseModuleQuery(agents, { status: 'active,disconnected', name: 'web', platform: 'windows', q: 'server' }));
  assert.equal(params.q, 'id!=000;(status=active,status=disconnected);name~web;(os.platform=windows)');
  assert.equal(params.search, 'server');
  assert.throws(() => agentQueryParams(agents, parseModuleQuery(agents, { name: 'a;id=000' })), /unsupported characters/);
});
