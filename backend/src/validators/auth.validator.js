import { z } from 'zod';

const username = z.string().trim().min(3).max(64).regex(/^[A-Za-z0-9._-]+$/, 'Usernames may contain letters, numbers, dots, underscores and hyphens');
const email = z.string().trim().toLowerCase().email('Enter a valid email address').max(254);
const fullName = z.string().trim().min(1, 'Full name is required').max(120).regex(/^[^<>\r\n]*$/, 'Invalid characters in name');
// Policy is enforced by utils/password.js; this only bounds input size.
const password = z.string().min(1, 'Password is required').max(128, 'Password is too long');

export const loginSchema = z.object({
  identifier: z.string().trim().min(1, 'Enter your username or email').max(254),
  password,
  remember: z.boolean().default(false),
});

export const setupSchema = z.object({
  setup_token: z.string().min(1, 'Setup token is required').max(500),
  full_name: fullName,
  username,
  email,
  password,
});

export const acceptInvitationSchema = z.object({ token: z.string().min(20).max(200), password });
export const invitationTokenSchema = z.object({ token: z.string().min(20).max(200) });

export const inviteUserSchema = z.object({
  full_name: fullName,
  email,
  username,
  role: z.string().min(1).max(100),
  additional_roles: z.array(z.string().max(100)).max(10).default([]),
});

export const updateUserSchema = z.object({
  full_name: fullName.optional(),
  email: email.optional(),
  role: z.string().min(1).max(100).optional(),
  additional_roles: z.array(z.string().max(100)).max(10).optional(),
});

export const forcePasswordSchema = z.object({ revoke_sessions: z.boolean().default(false) });

// Legacy exports kept for compatibility with older imports.
export const credentialsSchema = z.object({ username: z.string().min(3).max(120), password: z.string().min(12).max(200) });
export const createUserSchema = inviteUserSchema;
