import { randomInt } from 'node:crypto';
import { keyedHash } from './token.js';

/** Cryptographically secure 6-digit code (uniform over 000000–999999). */
export const generateOtp = () => String(randomInt(0, 1_000_000)).padStart(6, '0');

/** Bind the hash to the challenge id so identical codes in different challenges hash differently. */
export const hashOtp = (challengeId, otp) => keyedHash(`${challengeId}:${otp}`);

export const isOtpFormat = (value) => /^\d{6}$/.test(String(value || ''));

/** j***e@example.com */
export function maskEmail(email) {
  const [local = '', domain = ''] = String(email || '').split('@');
  if (!domain) return '';
  const visible = local.length <= 2 ? local[0] || '' : `${local[0]}${'*'.repeat(Math.min(6, local.length - 2))}${local.at(-1)}`;
  return `${visible}@${domain}`;
}
