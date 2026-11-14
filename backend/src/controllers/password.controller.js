import * as passwordService from '../services/password.service.js';
import { validate } from '../validators/validate.js';
import { changePasswordSchema, forgotPasswordSchema, resetPasswordSchema } from '../validators/password.validator.js';
import { verifyOtpSchema } from '../validators/otp.validator.js';
import { passwordProblems } from '../utils/password.js';
import { clientInfo } from '../utils/http.js';

export async function forgot(req, res) {
  const { email } = validate(forgotPasswordSchema, req.body);
  res.json(await passwordService.forgotPassword(email, clientInfo(req)));
}

export async function verifyResetOtp(req, res) {
  const body = validate(verifyOtpSchema, req.body);
  res.json(await passwordService.verifyResetOtp({ challengeId: body.challenge_id, otp: body.otp }));
}

export async function reset(req, res) {
  const body = validate(resetPasswordSchema, req.body);
  res.json(await passwordService.resetPassword({ resetToken: body.reset_token, password: body.password }, clientInfo(req)));
}

export async function change(req, res) {
  const body = validate(changePasswordSchema, req.body);
  res.json(await passwordService.changePassword(req.user, req.user.session_id, { currentPassword: body.current_password, newPassword: body.new_password }, clientInfo(req)));
}

/** Server-side policy check used by the strength indicator (no password is stored or logged). */
export function policy(req, res) {
  const problems = passwordProblems(String(req.body?.password || '').slice(0, 200), { username: req.body?.username, email: req.body?.email });
  res.json({ valid: problems.length === 0, problems });
}
