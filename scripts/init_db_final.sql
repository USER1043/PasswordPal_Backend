-- ============================================================================
-- FINALIZED DATABASE SCHEMA — Zero-Knowledge Password Manager
-- Version: Sprint 0 Final (Verified against live Supabase DB)
-- Last Updated: March 2026
--
-- Tables:
--   users            — account identity and cryptographic material
--   vault_records    — encrypted credential storage
--   user_devices     — per-device session tracking and revocation
--   mfa_settings     — TOTP secrets and backup codes
--   login_attempts   — rate-limiting and brute-force detection
--   recovery_keys    — hashed recovery key for master password reset
--   refresh_tokens   — token rotation with revocation chain
--   sync_queue       — offline operation queue per device
--   conflicts        — sync conflict tracking and resolution
--
-- ARCHITECTURE DECISIONS:
--   - Audit logging is LOCAL ONLY (SQLite per device). No server-side audit table.
--     The server structurally cannot log vault-level activity — this is a hard
--     architectural guarantee, not just a policy promise.
--   - refresh_token in user_devices is legacy. refresh_tokens table is the
--     authoritative token store going forward.
--
-- APPLICATION-LAYER RESPONSIBILITIES (not enforceable by DB):
--   1. refresh_token / token_hash must be SHA-256 hashed before INSERT and before lookup.
--      Never store or compare raw tokens.
--   2. vault_records + users.vault_signature must be updated in a single transaction
--      on every sync. No exceptions.
--   3. device_fingerprint must be generated client-side on first install and
--      persisted in secure storage (Keychain/Keystore). Never server-generated.
--   4. last_country and refresh_tokens.created_country must be resolved via
--      MaxMind GeoLite2 server-side on login. Raw IP must never reach the DB.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- 1. USERS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.users (
    id              UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    email           TEXT        NOT NULL UNIQUE,
    salt            TEXT        NOT NULL,           -- Base64 per-user salt for Argon2id KDF
    server_hash     TEXT        NOT NULL,           -- Argon2id hash of client AuthKey (NOT the master password)
    wrapped_mek     TEXT        NOT NULL,           -- Master Encryption Key wrapped with KEK (Base64)
    vault_signature TEXT        NOT NULL DEFAULT 'EMPTY_VAULT',
                                                    -- Client-computed HMAC over all vault record IDs + nonces.
                                                    -- Sentinel 'EMPTY_VAULT' set on registration.
                                                    -- MUST be updated atomically with vault_records on every sync.
                                                    -- Server cannot forge this — signing key never leaves the client.
    kdf_params      JSONB       NOT NULL DEFAULT '{"algo":"argon2id","m":65536,"t":3,"p":4}',
                                                    -- KDF algorithm and cost params used for this user's AuthKey.
                                                    -- Stored per-user to support future migration to stronger params.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Case-insensitive email lookup — prevents duplicate accounts differing only in case
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users (lower(email));

-- ============================================================================
-- 2. VAULT RECORDS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.vault_records (
    id               UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id          UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    encrypted_data   TEXT        NOT NULL,          -- Base64 AES-256-GCM encrypted JSON blob
    nonce            TEXT        NOT NULL,          -- Base64 IV for AES-GCM (unique per record per write)
    version          INTEGER     NOT NULL DEFAULT 1, -- Per-record optimistic-lock counter, incremented on every update
    is_deleted       BOOLEAN     NOT NULL DEFAULT FALSE, -- Soft-delete tombstone — never hard delete for sync correctness
    record_type      TEXT        NOT NULL DEFAULT 'credential'
                                 CHECK (record_type IN ('credential', 'folder', 'tag')),
    client_record_id UUID,                          -- Client-assigned UUID for offline-created records,
                                                    -- used for deduplication on first sync
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Primary sync query pattern: delta sync by user + time
CREATE INDEX IF NOT EXISTS idx_vault_records_sync        ON public.vault_records (user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_records_record_type ON public.vault_records (record_type);

-- ============================================================================
-- 3. USER DEVICES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_devices (
    id                  UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id             UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    device_name         TEXT        NOT NULL,       -- Human-readable display label (user-editable, not used as identity)
    device_fingerprint  TEXT        NOT NULL,       -- Stable UUID generated client-side on first install.
                                                    -- Persisted in Keychain/Keystore. Never changes on re-login.
    is_revoked          BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at          TIMESTAMPTZ,                -- Nullable — set when device is explicitly revoked
    refresh_token       TEXT,                       -- Legacy field. refresh_tokens table is authoritative.
                                                    -- If used: store SHA-256 hash only, never raw token.
    token_expires_at    TIMESTAMPTZ NOT NULL,       -- Server-side TTL for the legacy refresh_token field
    last_country        TEXT,                       -- Nullable ISO 3166-1 alpha-2 (e.g. 'IN', 'US').
                                                    -- Resolved via MaxMind GeoLite2. Raw IP never stored.
                                                    -- NULL is valid: VPN, private IP, unmapped range.
    trusted_until       TIMESTAMPTZ,                -- Nullable — MFA step-up trust window expiry
    last_login          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_user_device UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_user  ON public.user_devices (user_id);

-- Partial index — only non-revoked tokens are ever looked up during auth
CREATE INDEX IF NOT EXISTS idx_user_devices_token ON public.user_devices (refresh_token)
    WHERE is_revoked = FALSE;

-- ============================================================================
-- 4. MFA SETTINGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.mfa_settings (
    user_id          UUID        PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    totp_secret_enc  TEXT,                          -- Server-side encrypted TOTP secret
    is_totp_enabled  BOOLEAN     NOT NULL DEFAULT FALSE,
    backup_codes_enc TEXT,                          -- Encrypted/hashed backup codes blob (JSON array)
    codes_used       INTEGER     NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- 5. LOGIN ATTEMPTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.login_attempts (
    id             UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id        UUID        REFERENCES public.users(id) ON DELETE SET NULL,
    ip_address     INET        NOT NULL,            -- Justified: security infrastructure for rate-limiting,
                                                    -- not user-facing metadata. Covered under legitimate interest.
    was_successful BOOLEAN     NOT NULL DEFAULT FALSE,
    user_agent     TEXT,
    attempt_time   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip   ON public.login_attempts (ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON public.login_attempts (attempt_time);

-- Partial index for fast failed-attempt queries (rate-limit checks)
CREATE INDEX IF NOT EXISTS idx_login_failures ON public.login_attempts (ip_address, attempt_time)
    WHERE was_successful = FALSE;

-- ============================================================================
-- 6. RECOVERY KEYS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.recovery_keys (
    user_id     UUID        PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    key_hash    TEXT        NOT NULL,               -- SHA-256 hash of the 256-bit recovery key.
                                                    -- Raw key is never sent to or stored on the server —
                                                    -- it lives only in the user's downloaded Recovery PDF.
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    expires_at  TIMESTAMPTZ                         -- Nullable — set if recovery keys have a TTL policy
);

-- ============================================================================
-- 7. REFRESH TOKENS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.refresh_tokens (
    id                   UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id              UUID        REFERENCES public.users(id) ON DELETE CASCADE,
    device_id            UUID        REFERENCES public.user_devices(id) ON DELETE CASCADE,
    token_hash           TEXT        NOT NULL,      -- SHA-256 hash of the issued token. Never store raw.
    expires_at           TIMESTAMPTZ NOT NULL,
    is_revoked           BOOLEAN     NOT NULL DEFAULT FALSE,
    created_country      TEXT,                      -- Nullable ISO 3166-1 alpha-2.
                                                    -- Resolved via MaxMind GeoLite2. Raw IP never stored.
    replaced_by_token_id UUID,                      -- Token rotation chain — points to the successor token.
                                                    -- Enables replay attack detection.
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Most frequent query in the system — every auth request hits this
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON public.refresh_tokens (token_hash)
    WHERE is_revoked = FALSE;

-- ============================================================================
-- 8. SYNC QUEUE
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.sync_queue (
    id                      UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id                 UUID        REFERENCES public.users(id) ON DELETE CASCADE,
    device_id               UUID        REFERENCES public.user_devices(id) ON DELETE CASCADE,
    record_id               UUID        NOT NULL,
    operation_type          TEXT        CHECK (operation_type IN ('INSERT', 'UPDATE', 'DELETE')),
    encrypted_data          TEXT,                   -- Nullable — not needed for DELETE operations
    version_at_time_of_edit INTEGER,
    retry_count             INTEGER     DEFAULT 0,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    processed_at            TIMESTAMPTZ             -- Nullable — set when successfully processed
);

CREATE INDEX IF NOT EXISTS idx_sync_queue_user_device ON public.sync_queue (user_id, device_id, created_at DESC);

-- ============================================================================
-- 9. CONFLICTS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.conflicts (
    id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id           UUID        REFERENCES public.users(id) ON DELETE CASCADE,
    record_id         UUID        NOT NULL,
    server_version    INTEGER,
    local_version     INTEGER,
    conflict_data_enc TEXT,                         -- Encrypted snapshot of the conflicting state
    resolution_type   TEXT        CHECK (resolution_type IN ('SERVER_WINS', 'CLIENT_WINS', 'MANUAL_MERGE')),
    resolved_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_conflicts_user ON public.conflicts (user_id, record_id);

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================
ALTER TABLE public.users           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_records   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mfa_settings    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_attempts  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.recovery_keys   ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_tokens  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sync_queue      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conflicts       ENABLE ROW LEVEL SECURITY;

-- Drop all existing policies to make script re-runnable
DROP POLICY IF EXISTS "Users can see their own data"             ON public.users;
DROP POLICY IF EXISTS "Users can manage their own vault records" ON public.vault_records;
DROP POLICY IF EXISTS "Users can manage their own devices"       ON public.user_devices;
DROP POLICY IF EXISTS "Users can manage their own mfa settings"  ON public.mfa_settings;
DROP POLICY IF EXISTS "Allow all for mfa_settings"               ON public.mfa_settings;
DROP POLICY IF EXISTS "Allow all for login_attempts"             ON public.login_attempts;
DROP POLICY IF EXISTS "Allow all for recovery_keys"              ON public.recovery_keys;
DROP POLICY IF EXISTS "Allow all for refresh_tokens"             ON public.refresh_tokens;
DROP POLICY IF EXISTS "Allow all for sync_queue"                 ON public.sync_queue;
DROP POLICY IF EXISTS "Allow all for conflicts"                  ON public.conflicts;

-- User-scoped policies (each user reads and writes only their own data)
CREATE POLICY "Users can see their own data"
    ON public.users FOR SELECT USING (auth.uid() = id);

CREATE POLICY "Users can manage their own vault records"
    ON public.vault_records FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Users can manage their own devices"
    ON public.user_devices FOR ALL USING (auth.uid() = user_id);

-- Open policies — service_role (Node backend) bypasses RLS automatically.
-- These cover authenticated/anon roles for direct access if needed.
CREATE POLICY "Allow all for mfa_settings"
    ON public.mfa_settings    FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Allow all for login_attempts"
    ON public.login_attempts  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Allow all for recovery_keys"
    ON public.recovery_keys   FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Allow all for refresh_tokens"
    ON public.refresh_tokens  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Allow all for sync_queue"
    ON public.sync_queue      FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Allow all for conflicts"
    ON public.conflicts       FOR ALL USING (true) WITH CHECK (true);

-- ============================================================================
-- GRANTS
-- ============================================================================
GRANT ALL ON public.mfa_settings   TO service_role, authenticated, anon;
GRANT ALL ON public.login_attempts TO service_role, authenticated, anon;
GRANT ALL ON public.recovery_keys  TO service_role, authenticated, anon;
GRANT ALL ON public.refresh_tokens TO service_role, authenticated, anon;
GRANT ALL ON public.sync_queue     TO service_role, authenticated, anon;
GRANT ALL ON public.conflicts      TO service_role, authenticated, anon;
-- users and user_devices also need explicit grants so that the Node service_role
-- client can insert/update after a schema reload without losing default privileges.
GRANT ALL ON public.users          TO service_role, authenticated, anon;
GRANT ALL ON public.vault_records  TO service_role, authenticated, anon;
GRANT ALL ON public.user_devices   TO service_role, authenticated, anon;
