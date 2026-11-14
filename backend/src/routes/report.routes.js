import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { authenticate, requirePermission } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import { config } from '../config/index.js';
import * as reportController from '../controllers/report.controller.js';

const router = Router();
const auth = authenticate;
const permission = requirePermission;
const handle = (controller) => asyncHandler(controller);

const perMinute = (limit, message) => rateLimit({ windowMs: 60_000, limit, standardHeaders: true, legacyHeaders: false, ...(message ? { message: { error: message } } : {}) });
// Report generation queries OpenSearch heavily; keep per-client bursts small.
const generationLimit = perMinute(config.reports.generateRateLimit, 'Too many report requests. Try again in a minute.');
const scheduleWriteLimit = perMinute(config.reports.scheduleRateLimit, 'Too many schedule changes. Try again in a minute.');
const linkLimit = perMinute(30);

// Signed, expiring link from report emails. The token itself is the credential.
router.get('/reports/download/:token', linkLimit, handle(reportController.downloadWithToken));

router.get('/reports/catalog', auth, permission('reports:read'), handle(reportController.catalog));
router.post('/reports/generate', auth, permission('reports:generate'), generationLimit, handle(reportController.generate));

// `/report-history` is the existing endpoint, now paged and filterable.
router.get('/report-history', auth, permission('reports:read'), handle(reportController.history));
router.get('/report-history/:id', auth, permission('reports:read'), handle(reportController.historyItem));
router.get('/report-history/:id/download', auth, permission('reports:read'), handle(reportController.download));
router.delete('/report-history/:id', auth, permission('reports:generate'), handle(reportController.deleteHistory));

router.get('/report-templates', auth, permission('reports:read'), handle(reportController.templates));
router.post('/report-templates', auth, permission('reports:generate'), handle(reportController.createTemplate));
router.put('/report-templates/:id', auth, permission('reports:generate'), handle(reportController.updateTemplate));
router.delete('/report-templates/:id', auth, permission('reports:generate'), handle(reportController.deleteTemplate));

router.get('/report-schedules', auth, permission('reports:schedule'), handle(reportController.schedules));
router.post('/report-schedules', auth, permission('reports:schedule'), scheduleWriteLimit, handle(reportController.createSchedule));
router.post('/report-schedules/executions/:executionId/retry', auth, permission('reports:schedule'), generationLimit, handle(reportController.retryExecution));
router.get('/report-schedules/:id', auth, permission('reports:schedule'), handle(reportController.schedule));
router.put('/report-schedules/:id', auth, permission('reports:schedule'), scheduleWriteLimit, handle(reportController.updateSchedule));
router.delete('/report-schedules/:id', auth, permission('reports:schedule'), handle(reportController.deleteSchedule));
router.post('/report-schedules/:id/pause', auth, permission('reports:schedule'), handle(reportController.pauseSchedule));
router.post('/report-schedules/:id/resume', auth, permission('reports:schedule'), handle(reportController.resumeSchedule));
router.post('/report-schedules/:id/run', auth, permission('reports:schedule'), generationLimit, handle(reportController.runSchedule));
router.get('/report-schedules/:id/executions', auth, permission('reports:schedule'), handle(reportController.executions));

export default router;
