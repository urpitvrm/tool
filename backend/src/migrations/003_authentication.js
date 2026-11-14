// Authentication: account lifecycle, email OTP, refresh-token sessions, login and password history.
// Extends the existing `users` table and turns the never-checked `sessions` table into `user_sessions`.
export default {
  version: '003',
  description: 'Account lifecycle, OTP verifications, user sessions, login history, password history',
  up: `
    -- Users ------------------------------------------------------------------
    ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name TEXT NOT NULL DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by INTEGER REFERENCES users(id) ON DELETE SET NULL;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
    ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL; -- invited users set their own password
    UPDATE users SET status = 'deactivated' WHERE disabled AND status = 'active';
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_status_check;
    ALTER TABLE users ADD CONSTRAINT users_status_check
      CHECK (status IN ('invited', 'pending_verification', 'pending_approval', 'active', 'deactivated'));
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq ON users (lower(email)) WHERE email IS NOT NULL;
    CREATE INDEX IF NOT EXISTS users_status_idx ON users (status);

    -- Existing code reads users.disabled; keep it derived from status.
    CREATE OR REPLACE FUNCTION users_sync_disabled() RETURNS trigger AS $$
    BEGIN
      NEW.disabled := NEW.status <> 'active';
      NEW.updated_at := now();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    DROP TRIGGER IF EXISTS users_sync_disabled_trg ON users;
    CREATE TRIGGER users_sync_disabled_trg BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION users_sync_disabled();

    -- OTP / one-time tokens ---------------------------------------------------
    CREATE TABLE IF NOT EXISTS otp_verifications (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL CHECK (purpose IN ('LOGIN', 'EMAIL_VERIFICATION', 'PASSWORD_RESET', 'INVITATION')),
      otp_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      max_attempts INTEGER NOT NULL DEFAULT 5,
      resend_available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      consumed_at TIMESTAMPTZ,
      invalidated_at TIMESTAMPTZ,
      -- Short-lived grant issued after a verified PASSWORD_RESET OTP (hash only, single use).
      grant_hash TEXT,
      grant_expires_at TIMESTAMPTZ,
      grant_used_at TIMESTAMPTZ,
      remember BOOLEAN NOT NULL DEFAULT false,
      ip_address TEXT,
      user_agent TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS otp_user_purpose_idx ON otp_verifications (user_id, purpose, created_at DESC);
    CREATE INDEX IF NOT EXISTS otp_expires_idx ON otp_verifications (expires_at);
    CREATE UNIQUE INDEX IF NOT EXISTS otp_grant_hash_uq ON otp_verifications (grant_hash) WHERE grant_hash IS NOT NULL;
    -- Invitation links are looked up by token hash.
    CREATE UNIQUE INDEX IF NOT EXISTS otp_invitation_hash_uq ON otp_verifications (otp_hash) WHERE purpose = 'INVITATION';

    -- Sessions (the old table stored a hash of each JWT but was never checked) --
    DO $$ BEGIN
      IF to_regclass('public.sessions') IS NOT NULL AND to_regclass('public.user_sessions') IS NULL THEN
        ALTER TABLE sessions RENAME TO user_sessions;
      END IF;
    END $$;
    CREATE TABLE IF NOT EXISTS user_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE user_sessions ALTER COLUMN token_hash DROP NOT NULL;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS refresh_token_hash TEXT;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS previous_token_hash TEXT;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS device_information TEXT;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS ip_address TEXT;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS remember BOOLEAN NOT NULL DEFAULT false;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
    ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS revoke_reason TEXT;
    UPDATE user_sessions SET revoked_at = now(), revoke_reason = 'legacy' WHERE refresh_token_hash IS NULL AND revoked_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS user_sessions_refresh_uq ON user_sessions (refresh_token_hash) WHERE refresh_token_hash IS NOT NULL;
    CREATE INDEX IF NOT EXISTS user_sessions_previous_idx ON user_sessions (previous_token_hash) WHERE previous_token_hash IS NOT NULL;
    CREATE INDEX IF NOT EXISTS user_sessions_user_idx ON user_sessions (user_id, revoked_at, expires_at);

    -- Login history -------------------------------------------------------------
    CREATE TABLE IF NOT EXISTS login_history (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      email TEXT,
      identifier TEXT,
      ip_address TEXT,
      user_agent TEXT,
      login_status TEXT NOT NULL,
      failure_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS login_history_user_idx ON login_history (user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS login_history_ip_idx ON login_history (ip_address, created_at DESC);
    CREATE INDEX IF NOT EXISTS login_history_created_idx ON login_history (created_at DESC);

    -- Password history (reuse prevention) -------------------------------------
    CREATE TABLE IF NOT EXISTS password_history (
      id BIGSERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS password_history_user_idx ON password_history (user_id, created_at DESC);
    INSERT INTO password_history (user_id, password_hash)
      SELECT id, password_hash FROM users u
      WHERE password_hash IS NOT NULL AND NOT EXISTS (SELECT 1 FROM password_history h WHERE h.user_id = u.id);
  `,
};
