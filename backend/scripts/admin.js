#!/usr/bin/env node
// Administrative CLI for operators with server access.
//   npm run admin -- create-super-admin --username admin --email admin@example.com --name "Jane Admin"
//   npm run admin -- set-email --username admin --email admin@example.com
//   npm run admin -- unlock --username admin
//   npm run admin -- reset-password --username admin       (forces a new password at next sign-in)
// Passwords are read from the ADMIN_PASSWORD environment variable or prompted without echo.
import readline from 'node:readline';
import { pool, migrate } from '../src/config/db.js';
import { runMigrations } from '../src/migrations/index.js';
import * as users from '../src/models/user.model.js';
import { revokeAllSessions } from '../src/models/session.model.js';
import { assertPasswordPolicy, hashPassword } from '../src/utils/password.js';
import { audit } from '../src/config/db.js';

const [command, ...rest] = process.argv.slice(2);
const args = {};
for (let i = 0; i < rest.length; i += 2) args[rest[i].replace(/^--/, '')] = rest[i + 1];
const operator = { username: 'cli' };

function askHidden(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl._writeToOutput = (text) => { if (text.includes(question)) rl.output.write(text); };
    rl.question(question, (answer) => { rl.close(); process.stdout.write('\n'); resolve(answer); });
  });
}

async function password(username, email) {
  let value = process.env.ADMIN_PASSWORD;
  if (!value) {
    value = await askHidden('Password: ');
    if (value !== await askHidden('Confirm password: ')) throw new Error('Passwords do not match');
  }
  assertPasswordPolicy(value, { username, email });
  return hashPassword(value);
}

const required = (...keys) => { for (const key of keys) if (!args[key]) throw new Error(`--${key} is required`); };

async function main() {
  await migrate();
  await runMigrations();
  switch (command) {
    case 'create-super-admin': {
      required('username', 'email');
      if (await users.findByUsername(args.username)) throw new Error('That username already exists');
      if (await users.findByEmail(args.email)) throw new Error('That email is already in use');
      const roleId = await users.getBootstrapRoleId();
      const passwordHash = await password(args.username, args.email);
      // The operator has server access, so the address is trusted as verified.
      const created = await users.insertUser({ username: args.username, fullName: args.name || '', email: args.email.toLowerCase(), passwordHash, roleId, status: 'active', emailVerified: true });
      await audit({ ...operator, id: created.id }, 'auth.bootstrap', { method: 'cli', username: args.username });
      console.log(`Super Administrator "${args.username}" created. Sign in at the web console; a code will be emailed to ${args.email}.`);
      break;
    }
    case 'set-email': {
      required('username', 'email');
      const user = await users.findByUsername(args.username);
      if (!user) throw new Error('User not found');
      const other = await users.findByEmail(args.email);
      if (other && other.id !== user.id) throw new Error('That email is already in use');
      await pool.query('UPDATE users SET email = $2, email_verified = true, email_verified_at = now() WHERE id = $1', [user.id, args.email.toLowerCase()]);
      await audit(operator, 'user.set_email_cli', { id: user.id });
      console.log(`Email for "${args.username}" set and marked verified.`);
      break;
    }
    case 'unlock': {
      required('username');
      const user = await users.findByUsername(args.username);
      if (!user) throw new Error('User not found');
      await users.unlockUser(user.id);
      await audit(operator, 'user.unlock_cli', { id: user.id });
      console.log(`"${args.username}" unlocked.`);
      break;
    }
    case 'reset-password': {
      required('username');
      const user = await users.findByUsername(args.username);
      if (!user) throw new Error('User not found');
      await users.setPassword(user.id, await password(user.username, user.email));
      await users.setForcePasswordChange(user.id, true);
      const revoked = await revokeAllSessions(user.id, 'password_reset_cli');
      await audit(operator, 'user.password_reset_cli', { id: user.id, sessions_revoked: revoked });
      console.log(`Password for "${args.username}" reset; a new password will be required at next sign-in.`);
      break;
    }
    default:
      console.log('Commands: create-super-admin, set-email, unlock, reset-password (see scripts/admin.js header)');
      process.exitCode = 1;
  }
}

main()
  .catch((error) => { console.error(`Error: ${error.message}`); process.exitCode = 1; })
  .finally(() => pool.end());
