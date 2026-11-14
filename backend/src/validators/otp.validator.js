import { z } from 'zod';

const challengeId = z.string().uuid('Invalid verification request');

export const verifyOtpSchema = z.object({
  challenge_id: challengeId,
  otp: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code'),
});

export const resendOtpSchema = z.object({ challenge_id: challengeId });
