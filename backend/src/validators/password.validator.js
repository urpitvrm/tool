import { z } from 'zod';

const password = z.string().min(1, 'Password is required').max(128, 'Password is too long');

export const forgotPasswordSchema = z.object({ email: z.string().trim().toLowerCase().email('Enter a valid email address').max(254) });

export const resetPasswordSchema = z.object({
  reset_token: z.string().min(20).max(200),
  password,
  confirm_password: z.string().max(128),
}).refine((body) => body.password === body.confirm_password, { message: 'Passwords do not match', path: ['confirm_password'] });

export const changePasswordSchema = z.object({
  current_password: password,
  new_password: password,
  confirm_password: z.string().max(128),
}).refine((body) => body.new_password === body.confirm_password, { message: 'Passwords do not match', path: ['confirm_password'] });
