import { Router } from 'express';
import { authenticate, requirePermission } from '../middlewares/auth.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import * as userController from '../controllers/user.controller.js';

const router = Router();

router.post('/auth/register', asyncHandler(userController.register));
router.post('/auth/login', asyncHandler(userController.login));
router.get('/auth/me', authenticate, asyncHandler(userController.me));
router.get('/users', authenticate, requirePermission('admin:users'), asyncHandler(userController.listUsers));
router.post('/users', authenticate, requirePermission('admin:users'), asyncHandler(userController.createUser));
router.get('/roles', authenticate, requirePermission('admin:users'), asyncHandler(userController.listRoles));
router.get('/permissions', authenticate, requirePermission('admin:users'), asyncHandler(userController.listPermissions));

export default router;
