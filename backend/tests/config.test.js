import test from 'node:test';
import assert from 'node:assert/strict';
import { config } from '../src/config/index.js';

test('configuration parses OpenSearch node arrays', () => {
  assert.ok(Array.isArray(config.searchNodes));
  assert.ok(config.searchNodes.every((node) => typeof node === 'string'));
});

test('TLS certificate validation is enabled unless explicitly disabled', () => {
  assert.equal(typeof config.verifyTls, 'boolean');
});

test('upstream request timeouts have positive configured defaults', () => {
  assert.ok(config.opensearchRequestTimeoutMs > 0);
  assert.ok(config.wazuhRequestTimeoutMs > 0);
});

test('event index has a configurable non-empty fallback', () => {
  assert.equal(typeof config.eventsIndex, 'string');
  assert.ok(config.eventsIndex.length > 0);
});

test('Supabase PostgreSQL URI takes priority when configured', () => {
  if (process.env.SUPABASE_URL) {
    assert.equal(config.usingSupabase, true);
    assert.equal(config.databaseUrl, process.env.SUPABASE_URL);
    assert.match(config.databaseUrl, /^postgres(?:ql)?:\/\//i);
    let parsed;
    assert.doesNotThrow(() => { parsed = new URL(config.databaseUrl); });
    assert.ok(['postgres:', 'postgresql:'].includes(parsed.protocol));
    assert.ok(parsed.hostname.endsWith('.supabase.co') || parsed.hostname.endsWith('.pooler.supabase.com'), 'Use the PostgreSQL host shown in Supabase Database settings');
    assert.equal(/[\[\]<>]|placeholder|example/i.test(parsed.hostname), false, 'Replace example placeholders with the real Supabase database hostname');
  }
});

test('Supabase database connection requires verified TLS', () => {
  if (config.usingSupabase) assert.equal(config.databaseTls, true);
});
