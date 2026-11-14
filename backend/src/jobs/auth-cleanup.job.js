import { config } from '../config/index.js';
import { deleteExpired } from '../models/otp.model.js';
import { deleteOldLoginHistory, deleteStale } from '../models/session.model.js';

const INTERVAL_MS = 60 * 60 * 1000;
let timer = null;

/** Purge unusable OTP challenges, long-dead sessions and login history past retention. Idempotent. */
export async function runAuthCleanup() {
  const [otps, sessions, history] = await Promise.all([deleteExpired(24), deleteStale(7), deleteOldLoginHistory(config.auth.loginHistoryDays)]);
  if (otps || sessions || history) console.log(`Auth cleanup: ${otps} OTP challenges, ${sessions} sessions, ${history} login-history rows removed.`);
}

export function startAuthCleanup() {
  if (timer) return;
  const tick = () => runAuthCleanup().catch((error) => console.error('Auth cleanup failed:', error.message));
  tick();
  timer = setInterval(tick, INTERVAL_MS);
  timer.unref();
}

export function stopAuthCleanup() {
  if (timer) clearInterval(timer);
  timer = null;
}
