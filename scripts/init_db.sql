-- Enable UUID extension if not already enabled (standard for Supabase/PostgreSQL)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Create users table
-- This table stores the cryptographic identifiers and authentication data.
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT UNIQUE NOT NULL,
    salt TEXT NOT NULL,          -- Base64 encoded salt for Argon2id
    server_hash TEXT NOT NULL,   -- Argon2 hash of the client's AuthHash
    wrapped_mek TEXT NOT NULL,   -- Master Encryption Key wrapped with KEK (Base64)
    vault_signature TEXT,        -- SHA-256 hash of record_id:version pairs for sync
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Create vault_records table
-- Stores encrypted password records. The server cannot decrypt 'encrypted_data'.
CREATE TABLE IF NOT EXISTS public.vault_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),   -- Usually client-generated UUID
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    encrypted_data TEXT NOT NULL,                     -- Base64 encoded AES-GCM encrypted JSON blob
    nonce TEXT NOT NULL,                              -- Base64 encoded IV for AES-GCM
    version INTEGER NOT NULL DEFAULT 1,               -- Optimistic-locking version counter
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,        -- Soft-delete / tombstone flag for sync
    record_type TEXT NOT NULL DEFAULT 'credential'    -- Vault item type: credential | folder | tag
        CHECK (record_type IN ('credential', 'folder', 'tag')),
    client_record_id UUID,                            -- Optional client-side reference UUID
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),    -- Immutable creation timestamp
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()     -- Updated on every write
);

-- Indexes for faster sync and type-filter queries
CREATE INDEX IF NOT EXISTS idx_vault_records_user_id ON public.vault_records(user_id);
CREATE INDEX IF NOT EXISTS idx_vault_records_updated_at ON public.vault_records(updated_at);
CREATE INDEX IF NOT EXISTS idx_vault_records_record_type ON public.vault_records(record_type);

-- 3. Create user_devices table
-- Tracks active sessions/devices for security auditing.
CREATE TABLE IF NOT EXISTS public.user_devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL,
    last_login TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    refresh_token TEXT            -- Hashed or encrypted refresh token
);

-- Index for looking up devices by user
CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON public.user_devices(user_id);

-- 4. Create mfa_settings table
-- Stores TOTP secrets and backup codes separately from the users table.
CREATE TABLE IF NOT EXISTS public.mfa_settings (
    user_id UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    totp_secret_enc TEXT,              -- Server-side encrypted TOTP secret
    is_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes_enc TEXT,             -- Encrypted/hashed backup codes blob (JSON array)
    codes_used INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Create login_attempts table
-- Tracks login attempts for rate-limiting and security auditing.
CREATE TABLE IF NOT EXISTS public.login_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES public.users(id) ON DELETE SET NULL,
    ip_address TEXT NOT NULL,
    was_successful BOOLEAN NOT NULL DEFAULT FALSE,
    user_agent TEXT,
    attempt_time TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for efficient rate-limit queries
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON public.login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_time ON public.login_attempts(attempt_time);

-- Row Level Security (RLS)
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vault_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.mfa_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.login_attempts ENABLE ROW LEVEL SECURITY;

-- Drop existing policies first so script is re-runnable
DROP POLICY IF EXISTS "Users can see their own data" ON public.users;
DROP POLICY IF EXISTS "Users can manage their own vault records" ON public.vault_records;
DROP POLICY IF EXISTS "Users can manage their own devices" ON public.user_devices;
DROP POLICY IF EXISTS "Users can manage their own mfa settings" ON public.mfa_settings;

-- Recreate policies
CREATE POLICY "Users can see their own data" ON public.users FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can manage their own vault records" ON public.vault_records FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users can manage their own devices" ON public.user_devices FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "Users can manage their own mfa settings" ON public.mfa_settings FOR ALL USING (auth.uid() = user_id);

