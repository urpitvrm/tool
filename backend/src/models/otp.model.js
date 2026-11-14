import { randomUUID } from 'node:crypto';
import { pool } from '../config/db.js';

/**
 * Create a challenge and invalidate any still-open challenge of the same purpose for the user.
 * `hashFor(id)` receives the new id so the stored hash can be bound to it.
 */
export async function createChallenge({ userId, purpose, hashFor, expiresMinutes, maxAttempts, resendSeconds, remember = false, ip, userAgent }) {
  const id = randomUUID();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (userId) {
      await client.query(
        `UPDATE otp_verifications SET invalidated_at = now()
         WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND invalidated_at IS NULL`,
        [userId, purpose],
      );
    }
    const { rows } = await client.query(
      `INSERT INTO otp_verifications(id, user_id, purpose, otp_hash, expires_at, max_attempts, resend_available_at, remember, ip_address, user_agent)
       VALUES($1, $2, $3, $4, now() + make_interval(mins => $5), $6, now() + make_interval(secs => $7), $8, $9, $10)
       RETURNING id, purpose, expires_at, resend_available_at, max_attempts`,
      [id, userId, purpose, hashFor(id), expiresMinutes, maxAttempts, resendSeconds, remember, ip, userAgent],
    );
    await client.query('COMMIT');
    return rows[0];
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function findChallenge(id) {
  const { rows } = await pool.query('SELECT * FROM otp_verifications WHERE id = $1', [id]);
  return rows[0] || null;
}

/**
 * Count one verification attempt atomically. Returns the row (with its hash) only while the
 * challenge is still open; concurrent requests cannot exceed max_attempts.
 */
export async function recordAttempt(id, purpose) {
  const { rows } = await pool.query(
    `UPDATE otp_verifications SET attempts = attempts + 1
     WHERE id = $1 AND purpose = $2 AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > now() AND attempts < max_attempts
     RETURNING *`,
    [id, purpose],
  );
  return rows[0] || null;
}

/** Single use: only the first caller gets the row back. */
export async function consumeChallenge(id) {
  const { rows } = await pool.query('UPDATE otp_verifications SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL RETURNING *', [id]);
  return rows[0] || null;
}

export async function invalidateChallenge(id) {
  await pool.query('UPDATE otp_verifications SET invalidated_at = now() WHERE id = $1 AND consumed_at IS NULL', [id]);
}

export async function countRecent(userId, purpose, minutes) {
  const { rows } = await pool.query(
    'SELECT COUNT(*)::int AS n FROM otp_verifications WHERE user_id = $1 AND purpose = $2 AND created_at > now() - make_interval(mins => $3)',
    [userId, purpose, minutes],
  );
  return rows[0].n;
}

// ---- Password-reset grant (issued after a verified reset OTP) ------------------------------

export async function setGrant(id, grantHash, minutes) {
  await pool.query('UPDATE otp_verifications SET grant_hash = $2, grant_expires_at = now() + make_interval(mins => $3) WHERE id = $1', [id, grantHash, minutes]);
}

export async function consumeGrant(grantHash) {
  const { rows } = await pool.query(
    `UPDATE otp_verifications SET grant_used_at = now()
     WHERE grant_hash = $1 AND purpose = 'PASSWORD_RESET' AND grant_used_at IS NULL AND grant_expires_at > now()
     RETURNING user_id`,
    [grantHash],
  );
  return rows[0] || null;
}

export async function findOpenGrant(grantHash) {
  const { rows } = await pool.query(
    "SELECT user_id FROM otp_verifications WHERE grant_hash = $1 AND purpose = 'PASSWORD_RESET' AND grant_used_at IS NULL AND grant_expires_at > now()",
    [grantHash],
  );
  return rows[0] || null;
}

// ---- Invitations (token hash stored in otp_hash) ------------------------------------------

export async function findOpenInvitation(tokenHash) {
  const { rows } = await pool.query(
    `SELECT * FROM otp_verifications WHERE otp_hash = $1 AND purpose = 'INVITATION'
     AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > now()`,
    [tokenHash],
  );
  return rows[0] || null;
}

export async function consumeInvitation(tokenHash, db = pool) {
  const { rows } = await db.query(
    `UPDATE otp_verifications SET consumed_at = now()
     WHERE otp_hash = $1 AND purpose = 'INVITATION' AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > now()
     RETURNING user_id`,
    [tokenHash],
  );
  return rows[0] || null;
}

/** Remove challenges that can no longer be used. */
export async function deleteExpired(olderThanHours = 24) {
  const { rowCount } = await pool.query(
    `DELETE FROM otp_verifications WHERE GREATEST(expires_at, COALESCE(grant_expires_at, expires_at)) < now() - make_interval(hours => $1)`,
    [olderThanHours],
  );
  return rowCount;
}
