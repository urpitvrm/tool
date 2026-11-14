import * as authService from '../services/auth.service.js';
import { resendOtp } from '../services/otp.service.js';
import { validate } from '../validators/validate.js';
import { resendOtpSchema, verifyOtpSchema } from '../validators/otp.validator.js';
import { clientInfo } from '../utils/http.js';
import { sendAuthenticated } from './auth.controller.js';

export async function resend(req, res) {
  const { challenge_id: challengeId } = validate(resendOtpSchema, req.body);
  res.json({ status: 'otp_sent', challenge: await resendOtp(challengeId, clientInfo(req)) });
}

export async function verifyEmail(req, res) {
  const body = validate(verifyOtpSchema, req.body);
  sendAuthenticated(res, await authService.verifyEmail({ challengeId: body.challenge_id, otp: body.otp }, clientInfo(req)));
}
