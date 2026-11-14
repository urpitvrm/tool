import test from 'node:test';
import assert from 'node:assert/strict';
import { credentialsSchema, createUserSchema } from '../src/validators/auth.validator.js';
import { agentOperationSchema, incidentCreateSchema, indexOperationSchema } from '../src/validators/api.validator.js';

test('credentials retain the existing username and password constraints', () => {
  assert.equal(credentialsSchema.safeParse({ username: 'analyst', password: 'a-long-enough-secret' }).success, true);
  assert.equal(credentialsSchema.safeParse({ username: 'ab', password: 'short' }).success, false);
  // Users are now invited (no administrator-chosen password).
  assert.equal(createUserSchema.safeParse({ full_name: 'An Analyst', email: 'analyst@example.com', username: 'analyst', role: 'Analyst' }).success, true);
});

test('agent and index operations require explicit confirmation', () => {
  assert.equal(agentOperationSchema.safeParse({ operation: 'restart', confirm: true }).success, true);
  assert.equal(agentOperationSchema.safeParse({ operation: 'remove', confirm: false }).success, true);
  assert.equal(indexOperationSchema.safeParse({ operation: 'delete', confirm: true }).success, true);
  assert.equal(indexOperationSchema.safeParse({ operation: 'delete' }).success, false);
});

test('incident create schema preserves defaults', () => {
  const result = incidentCreateSchema.parse({ title: 'Test incident' });
  assert.equal(result.severity, 'medium');
  assert.equal(result.description, '');
});
