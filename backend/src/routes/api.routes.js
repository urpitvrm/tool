import { Router } from 'express';
import { authenticate, requirePermission } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import * as apiController from '../controllers/api.controller.js';

const router = Router();
const auth = authenticate;
const permission = requirePermission;
const handle = (controller) => asyncHandler(controller);

router.get('/dashboard', auth, permission('dashboard:read'), handle(apiController.dashboard));
router.get('/events/export', auth, permission('events:read'), handle(apiController.exportEvents));
router.get('/events', auth, permission('events:read'), handle(apiController.events));
router.get('/agents', auth, permission('agents:read'), handle(apiController.agents));
router.get('/agents/summary', auth, permission('agents:read'), handle(apiController.agentSummary));
router.get('/agents/:id', auth, permission('agents:read'), handle(apiController.agentDetail));
router.get('/agent-groups', auth, permission('agents:read'), handle(apiController.agentGroups));
router.post('/agents/:id/operations', auth, permission('agents:manage'), handle(apiController.agentOperation));

router.get('/indices', auth, permission('indices:read'), handle(apiController.indices));
router.get('/indices/:name/mappings', auth, permission('indices:read'), handle(apiController.indexMappings));
router.get('/indices/:name/search', auth, permission('indices:read'), handle(apiController.indexSearch));
router.post('/indices/:name/operations', auth, permission('indices:manage'), handle(apiController.indexOperation));
router.get('/cluster/health', auth, permission('indices:read'), handle(apiController.clusterHealth));

router.get('/incidents', auth, permission('incidents:write'), handle(apiController.incidents));
router.post('/incidents', auth, permission('incidents:write'), handle(apiController.createIncident));
router.patch('/incidents/:id', auth, permission('incidents:write'), handle(apiController.updateIncident));
router.post('/incidents/:id/comments', auth, permission('incidents:write'), handle(apiController.incidentComment));
router.get('/audit-logs', auth, permission('audit:read'), handle(apiController.auditLogs));

const modulePermissions = {
  vulnerabilities: 'events:read', sca: 'events:read', fim: 'events:read', rootcheck: 'events:read',
  malware: 'events:read', rules: 'events:read', decoders: 'events:read', authentication: 'events:read',
  mitre: 'events:read', compliance: 'compliance:read', threatIntelligence: 'events:read', assets: 'agents:read',
};
for (const [module, permissionKey] of Object.entries(modulePermissions)) {
  router.get(`/${module}`, auth, permission(permissionKey), handle(apiController.moduleData(module)));
}

router.post('/saved-searches', auth, permission('events:read'), handle(apiController.saveSearch));
router.get('/saved-searches', auth, permission('events:read'), handle(apiController.savedSearches));
router.get('/custom-dashboards', auth, permission('dashboard:read'), handle(apiController.dashboards));
router.post('/custom-dashboards', auth, permission('dashboard:read'), handle(apiController.saveDashboard));
router.get('/custom-dashboards/:id', auth, permission('dashboard:read'), handle(apiController.savedDashboard));
router.put('/custom-dashboards/:id', auth, permission('dashboard:read'), handle(apiController.updateDashboard));
router.delete('/custom-dashboards/:id', auth, permission('dashboard:read'), handle(apiController.deleteDashboard));
// GET /report-history now lives in report.routes.js (same path and permission, paged and filterable).
router.get('/notification-rules', auth, permission('admin:settings'), handle(apiController.notificationRules));
router.post('/notification-rules', auth, permission('admin:settings'), handle(apiController.createNotificationRule));
router.get('/active-response', auth, permission('agents:manage'), apiController.activeResponse);
router.get('/settings', auth, permission('admin:settings'), handle(apiController.settings));
router.put('/settings/:key', auth, permission('admin:settings'), handle(apiController.updateSetting));

export default router;
