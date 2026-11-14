import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { authenticate } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import * as moduleController from '../controllers/module.controller.js';

const router = Router();
const auth = authenticate;
const module = moduleController.requireModule;
const handle = (controller) => asyncHandler(controller);
const exportLimit = rateLimit({ windowMs: 60_000, limit: 10, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many exports. Try again in a minute.' } });

// Two-tab module workspaces (Dashboard / Search). All endpoints share one filter parser,
// so KPIs, charts, the table and exports always describe the same records.
router.get('/modules', auth, handle(moduleController.list));
router.get('/modules/:module', auth, module, moduleController.definition);
router.get('/modules/:module/fields', auth, module, handle(moduleController.fields));
router.get('/modules/:module/aggregations', auth, module, handle(moduleController.aggregations));
router.get('/modules/:module/records', auth, module, handle(moduleController.records));
router.get('/modules/:module/values', auth, module, handle(moduleController.values));
router.get('/modules/:module/export', auth, module, exportLimit, handle(moduleController.exportRecords));
router.get('/modules/:module/preferences/:table', auth, module, handle(moduleController.getPreference));
router.put('/modules/:module/preferences/:table', auth, module, handle(moduleController.savePreference));
router.delete('/modules/:module/preferences/:table', auth, module, handle(moduleController.resetPreference));

export default router;
