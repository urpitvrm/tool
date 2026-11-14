import { z } from 'zod';
import * as moduleService from '../services/module.service.js';
import { MODULES, publicModule } from '../constants/modules.js';
import * as siemModel from '../models/siem.model.js';
import { validate } from '../validators/validate.js';

const COMPLIANCE = new Set(['compliance', 'pci_dss', 'nist_800_53', 'gdpr', 'hipaa', 'cis_controls', 'iso_27001']);
export const modulePermission = (key) => (key === 'agents' ? 'agents:read' : COMPLIANCE.has(key) ? 'compliance:read' : 'events:read');

/** Resolve :module and enforce that module's read permission. */
export async function requireModule(req, res, next) {
  try {
    const module = moduleService.getModule(req.params.module);
    if (!req.user.permissions.includes(modulePermission(module.key))) {
      return res.status(403).json({ error: 'Permission denied', permission: modulePermission(module.key) });
    }
    req.module = module;
    return next();
  } catch (error) {
    return next(error);
  }
}

export async function list(req, res) {
  const visible = [];
  for (const module of Object.values(MODULES)) {
    if (req.user.permissions.includes(modulePermission(module.key))) visible.push(publicModule(module));
  }
  res.json(visible);
}

export function definition(req, res) {
  res.json(publicModule(req.module));
}

export async function fields(req, res) {
  res.json(await moduleService.moduleFields(req.module.key));
}

export async function aggregations(req, res) {
  res.json(await moduleService.aggregate(req.module.key, req.query, req.query.scope === 'search' ? 'search' : 'dashboard'));
}

export async function records(req, res) {
  res.json(await moduleService.records(req.module.key, req.query));
}

export async function values(req, res) {
  res.json(await moduleService.fieldValues(req.module.key, req.query));
}

export async function exportRecords(req, res) {
  await moduleService.exportRecords(req.module.key, req.query, res);
}

// ---- Column preferences (per user, module and table) -----------------------------------------

const tableKey = (value) => (['search', 'dashboard'].includes(value) ? value : 'search');
const preferenceSchema = z.object({
  columns: z.array(z.string().max(200).regex(/^[\w.@-]+$/, 'Invalid column key')).min(1, 'Select at least one column').max(80),
  page_size: z.number().int().min(1).max(200).optional(),
});

export async function getPreference(req, res) {
  res.json(await siemModel.getTablePreference(req.user.id, req.module.key, tableKey(req.params.table)) || { columns: null });
}

export async function savePreference(req, res) {
  const body = validate(preferenceSchema, req.body);
  res.json(await siemModel.saveTablePreference(req.user.id, req.module.key, tableKey(req.params.table), [...new Set(body.columns)], body.page_size));
}

export async function resetPreference(req, res) {
  await siemModel.deleteTablePreference(req.user.id, req.module.key, tableKey(req.params.table));
  res.status(204).end();
}
