import { Router } from 'express';
import { authenticate, identify } from '../middlewares/auth.middleware.js';
import * as limits from '../middlewares/rate-limit.middleware.js';
import { asyncHandler } from '../utils/helpers.js';
import * as authController from '../controllers/auth.controller.js';
import * as otpController from '../controllers/otp.controller.js';
import * as passwordController from '../controllers/password.controller.js';
import * as userController from '../controllers/user.controller.js';

const router = Router();
const handle = (controller) => asyncHandler(controller);

// ---- Public ---------------------------------------------------------------------------------
router.get('/auth/csrf', authController.csrf);
router.get('/auth/setup-status', handle(authController.setupStatus));
router.post('/auth/setup', limits.sensitiveIpLimit, handle(authController.setup));

router.post('/auth/login', limits.loginIpLimit, limits.loginAccountLimit, handle(authController.login));
router.post('/auth/verify-login-otp', limits.otpIpLimit, limits.otpChallengeLimit, handle(authController.verifyLoginOtp));
router.post('/auth/verify-email', limits.otpIpLimit, limits.otpChallengeLimit, handle(otpController.verifyEmail));
router.post('/auth/resend-otp', limits.resendIpLimit, limits.otpChallengeLimit, handle(otpController.resend));

router.post('/auth/forgot-password', limits.recoveryIpLimit, limits.recoveryAccountLimit, handle(passwordController.forgot));
router.post('/auth/verify-reset-otp', limits.otpIpLimit, limits.otpChallengeLimit, handle(passwordController.verifyResetOtp));
router.post('/auth/reset-password', limits.sensitiveIpLimit, handle(passwordController.reset));
router.post('/auth/password-policy', limits.sensitiveIpLimit, passwordController.policy);

router.post('/auth/invitation', limits.sensitiveIpLimit, handle(userController.invitationInfo));
router.post('/auth/accept-invitation', limits.sensitiveIpLimit, handle(userController.acceptInvitation));

router.post('/auth/refresh-token', limits.refreshIpLimit, handle(authController.refreshToken));
router.post('/auth/logout', identify, handle(authController.logout));

// ---- Authenticated --------------------------------------------------------------------------
router.get('/auth/me', authenticate, handle(authController.me));
router.post('/auth/change-password', limits.sensitiveIpLimit, authenticate, handle(passwordController.change));
router.post('/auth/logout-all', authenticate, handle(authController.logoutAll));
router.get('/auth/sessions', authenticate, handle(authController.sessions));
router.delete('/auth/sessions/:id', authenticate, handle(authController.deleteSession));
router.get('/auth/login-history', authenticate, handle(authController.loginHistory));

// Removed: open first-user registration. Use /auth/setup (requires AUTH_SETUP_TOKEN) or the CLI.
router.post('/auth/register', (_req, res) => res.status(410).json({
  error: 'Open registration has been removed. Create the first Super Administrator with /auth/setup or the admin CLI.', code: 'REGISTRATION_REMOVED',
}));

export default router;
