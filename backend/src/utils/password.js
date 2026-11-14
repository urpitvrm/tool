import argon2 from 'argon2';

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

// Frequently breached passwords and patterns (normalized: lower-case, digits/symbols stripped at the ends).
const COMMON = new Set([
  'password', 'passw0rd', 'password1', 'password123', 'qwerty', 'qwertyuiop', 'qwerty123', 'letmein', 'welcome', 'welcome1',
  'admin', 'administrator', 'admin123', 'root', 'toor', 'changeme', 'default', 'iloveyou', 'monkey', 'dragon', 'football',
  'baseball', 'superman', 'batman', 'trustno1', 'sunshine', 'princess', 'master', 'shadow', 'michael', 'abc123', '123456',
  '1234567890', '12345678', '123456789', '111111', '000000', '1q2w3e4r', '1qaz2wsx', 'zaq12wsx', 'asdfghjkl', 'secret',
  'security', 'siem', 'wazuh', 'opensearch', 'sentinel', 'p@ssw0rd', 'p@ssword', 'summer', 'winter', 'spring', 'autumn',
  'company', 'login', 'access', 'starwars', 'whatever', 'computer', 'internet', 'service', 'qazwsx', 'pa55word',
]);

function normalize(value) {
  return String(value).toLowerCase().replace(/^[^a-z]+|[^a-z]+$/g, '').replace(/@/g, 'a').replace(/0/g, 'o').replace(/\$/g, 's');
}

/** Returns a list of unmet rules (empty = acceptable). */
export function passwordProblems(password, { username = '', email = '' } = {}) {
  const value = String(password || '');
  const problems = [];
  if (value.length < PASSWORD_MIN_LENGTH) problems.push(`be at least ${PASSWORD_MIN_LENGTH} characters long`);
  if (value.length > PASSWORD_MAX_LENGTH) problems.push(`be at most ${PASSWORD_MAX_LENGTH} characters long`);
  if (!/[a-z]/.test(value)) problems.push('include a lowercase letter');
  if (!/[A-Z]/.test(value)) problems.push('include an uppercase letter');
  if (!/\d/.test(value)) problems.push('include a number');
  if (!/[^A-Za-z0-9]/.test(value)) problems.push('include a special character');
  if (/(.)\1{3,}/.test(value)) problems.push('not repeat a character 4 or more times in a row');
  const lower = value.toLowerCase();
  const identities = [username, String(email).split('@')[0]].map((item) => String(item).toLowerCase()).filter((item) => item.length >= 3);
  if (identities.some((item) => lower.includes(item))) problems.push('not contain your username or email');
  const normalized = normalize(value);
  if (COMMON.has(lower) || COMMON.has(normalized) || [...COMMON].some((word) => word.length >= 6 && normalized === word.repeat(2))) {
    problems.push('not be a commonly used password');
  }
  return problems;
}

export function assertPasswordPolicy(password, identity) {
  const problems = passwordProblems(password, identity);
  if (problems.length) throw Object.assign(new Error(`Password must ${problems.join('; ')}.`), { status: 422, code: 'PASSWORD_POLICY' });
}

export const hashPassword = (password) => argon2.hash(password, { type: argon2.argon2id });

export async function verifyPassword(hash, password) {
  if (!hash) return false;
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

// Verifying against a real hash for unknown accounts keeps response timing uniform.
let dummyHash;
export async function burnPasswordCheck(password) {
  dummyHash ||= await hashPassword('timing-equalization-placeholder-Aa1!');
  await verifyPassword(dummyHash, password || 'x');
}
