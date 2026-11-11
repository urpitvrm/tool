import { z } from 'zod';

export const credentialsSchema = z.object({
  username: z.string().min(3).max(120),
  password: z.string().min(12).max(200),
});

export const createUserSchema = credentialsSchema.extend({ role: z.string() });
