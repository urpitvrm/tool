import { Router } from 'express';
import { authenticate, requirePermission } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import * as userController from '../controllers/user.controller.js';

// Authentication endpoints live in auth.routes.js; this router is user and role administration.
const router = Router();
const admin = [authenticate, requirePermission('admin:users')];
const handle = (controller) => asyncHandler(controller);

router.get('/users', ...admin, handle(userController.listUsers));
router.post('/users', ...admin, handle(userController.createUser));
router.get('/users/:id', ...admin, handle(userController.getUser));
router.patch('/users/:id', ...admin, handle(userController.updateUser));
router.post('/users/:id/activate', ...admin, handle(userController.activate));
router.post('/users/:id/deactivate', ...admin, handle(userController.deactivate));
router.post('/users/:id/unlock', ...admin, handle(userController.unlock));
router.post('/users/:id/force-password-change', ...admin, handle(userController.forcePasswordChange));
router.post('/users/:id/resend-invitation', ...admin, handle(userController.resendInvitation));
router.get('/users/:id/sessions', ...admin, handle(userController.userSessions));
router.delete('/users/:id/sessions', ...admin, handle(userController.revokeSessions));
router.get('/users/:id/login-history', authenticate, requirePermission('admin:users'), handle(userController.loginHistory));
router.get('/roles', ...admin, handle(userController.listRoles));
router.get('/permissions', ...admin, handle(userController.listPermissions));

export default router;
