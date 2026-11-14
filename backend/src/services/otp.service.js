import { config } from '../config/index.js';
import * as otpModel from '../models/otp.model.js';
import { findById } from '../models/user.model.js';
import { generateOtp, hashOtp, isOtpFormat, maskEmail } from '../utils/otp.js';
import { randomToken, safeEqual } from '../utils/token.js';
import { sendEmailVerificationOtp, sendLoginOtp, sendPasswordResetOtp } from './auth-email.service.js';

export const PURPOSES = { LOGIN: 'LOGIN', EMAIL_VERIFICATION: 'EMAIL_VERIFICATION', PASSWORD_RESET: 'PASSWORD_RESET' };
const fail = (status, code, message, extra = {}) => Object.assign(new Error(message), { status, code, ...extra });
const SENDERS = {
  LOGIN: (user, otp, client) => sendLoginOtp(user, otp, client),
  EMAIL_VERIFICATION: (user, otp) => sendEmailVerificationOtp(user, otp),
  PASSWORD_RESET: (user, otp, client) => sendPasswordResetOtp(user, otp, client),
};

export function publicChallenge(challenge, email) {
  return {
    challenge_id: challenge.id,
    purpose: challenge.purpose,
    expires_at: challenge.expires_at,
    resend_available_at: challenge.resend_available_at,
    max_attempts: challenge.max_attempts,
    destination: maskEmail(email),
  };
}

/**
 * Create a new code for `purpose`, invalidating the previous one, and email it.
 * The plain code exists only in memory here; it is never logged or returned.
 */
export async function issueOtp(user, purpose, { client, remember = false, background = false } = {}) {
  const recent = await otpModel.countRecent(user.id, purpose, 15);
  if (recent >= config.auth.otpMaxPerWindow) {
    throw fail(429, 'OTP_RATE_LIMITED', 'Too many verification codes were requested. Wait 15 minutes and try again.');
  }
  const otp = generateOtp();
  const challenge = await otpModel.createChallenge({
    userId: user.id, purpose, hashFor: (id) => hashOtp(id, otp),
    expiresMinutes: config.auth.otpMinutes, maxAttempts: config.auth.otpMaxAttempts, resendSeconds: config.auth.otpResendSeconds,
    remember, ip: client?.ip, userAgent: client?.userAgent,
  });
  const send = SENDERS[purpose](user, otp, client).catch(async (error) => {
    await otpModel.invalidateChallenge(challenge.id).catch(() => {});
    console.error(`Verification email (${purpose}) could not be delivered: ${error.code || error.message}`);
    throw error.code === 'SMTP_NOT_CONFIGURED' ? error
      : fail(503, 'EMAIL_DELIVERY_FAILED', 'The verification email could not be sent. Try again shortly or contact your administrator.');
  });
  if (background) send.catch(() => {});
  else await send;
  return publicChallenge(challenge, user.email);
}

/**
 * Verify a code. Attempts are counted atomically before comparison and a code can be
 * consumed exactly once, so concurrent or replayed submissions cannot succeed twice.
 */
export async function verifyOtp(challengeId, purpose, otp) {
  if (!isOtpFormat(otp)) throw fail(422, 'OTP_INVALID_FORMAT', 'Enter the 6-digit code.');
  const attempt = await otpModel.recordAttempt(challengeId, purpose);
  if (!attempt) {
    const existing = await otpModel.findChallenge(challengeId);
    if (existing && existing.purpose === purpose && existing.attempts >= existing.max_attempts && !existing.consumed_at) {
      throw fail(429, 'OTP_ATTEMPTS_EXCEEDED', 'Too many incorrect codes. Request a new code.', { userId: existing.user_id });
    }
    throw fail(400, 'OTP_EXPIRED', 'This code has expired or was already used. Request a new code.');
  }
  if (!safeEqual(attempt.otp_hash, hashOtp(attempt.id, otp))) {
    const remaining = attempt.max_attempts - attempt.attempts;
    if (remaining <= 0) await otpModel.invalidateChallenge(attempt.id);
    throw fail(400, remaining > 0 ? 'OTP_INCORRECT' : 'OTP_ATTEMPTS_EXCEEDED',
      remaining > 0 ? `Incorrect code. ${remaining} attempt${remaining === 1 ? '' : 's'} left.` : 'Too many incorrect codes. Request a new code.',
      { attemptsRemaining: Math.max(0, remaining), userId: attempt.user_id, exhausted: remaining <= 0 });
  }
  const consumed = await otpModel.consumeChallenge(attempt.id);
  if (!consumed) throw fail(400, 'OTP_EXPIRED', 'This code was already used. Request a new code.');
  return consumed;
}

/**
 * A password-reset challenge for an address with no eligible account. It is a real row whose hash
 * can never match, so verification, attempt counting and resend behave exactly like a real one.
 */
export async function issueDecoy(client) {
  const challenge = await otpModel.createChallenge({
    userId: null, purpose: PURPOSES.PASSWORD_RESET, hashFor: () => randomToken(),
    expiresMinutes: config.auth.otpMinutes, maxAttempts: config.auth.otpMaxAttempts, resendSeconds: config.auth.otpResendSeconds,
    ip: client?.ip, userAgent: client?.userAgent,
  });
  const { destination: _none, ...rest } = publicChallenge(challenge, '');
  return rest;
}

/** Issue a replacement code after the cooldown; the old challenge is invalidated. */
export async function resendOtp(challengeId, client) {
  const challenge = await otpModel.findChallenge(challengeId);
  if (!challenge || !SENDERS[challenge.purpose] || challenge.consumed_at || (!challenge.user_id && challenge.purpose !== PURPOSES.PASSWORD_RESET)) {
    throw fail(400, 'OTP_EXPIRED', 'This verification request is no longer valid. Start again.');
  }
  // Old verification requests must be restarted from the beginning (e.g. re-enter the password).
  if (Date.now() - new Date(challenge.created_at).getTime() > 30 * 60_000) {
    throw fail(400, 'OTP_EXPIRED', 'This verification request is no longer valid. Start again.');
  }
  const wait = Math.ceil((new Date(challenge.resend_available_at).getTime() - Date.now()) / 1000);
  if (wait > 0) throw fail(429, 'OTP_RESEND_COOLDOWN', `You can request a new code in ${wait} seconds.`, { retryAfter: wait });
  if (!challenge.user_id) {
    await otpModel.invalidateChallenge(challenge.id);
    return issueDecoy(client);
  }
  const user = await findById(challenge.user_id);
  if (!user || !user.email || ['deactivated'].includes(user.status)) throw fail(400, 'OTP_EXPIRED', 'This verification request is no longer valid. Start again.');
  const next = await issueOtp(user, challenge.purpose, { client, remember: challenge.remember, background: challenge.purpose === PURPOSES.PASSWORD_RESET });
  if (challenge.purpose === PURPOSES.PASSWORD_RESET) delete next.destination;
  return next;
}
