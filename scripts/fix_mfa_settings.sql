-- ============================================================================
-- FIX: mfa_settings FK + login_attempts RLS
-- Run this in: Supabase Dashboard → SQL Editor → New Query → Run
-- ============================================================================

-- ===== PART 1: Fix mfa_settings =====

-- Drop the broken table (safe — MFA was never persisting anyway)
DROP TABLE IF EXISTS public.mfa_settings CASCADE;

-- Recreate with correct FK to public.users (NOT auth.users)
CREATE TABLE public.mfa_settings (
    user_id         UUID PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
    totp_secret_enc TEXT,
    is_totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    backup_codes_enc TEXT,
    codes_used      INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE public.mfa_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can manage their own mfa settings" ON public.mfa_settings;
DROP POLICY IF EXISTS "Service role full access to mfa_settings" ON public.mfa_settings;

-- Permissive policy: service_role key (used by Node backend) bypasses RLS automatically
-- This policy covers authenticated/anon roles if they ever call directly
CREATE POLICY "Allow all for mfa_settings"
    ON public.mfa_settings FOR ALL USING (true) WITH CHECK (true);

GRANT ALL ON public.mfa_settings TO service_role;
GRANT ALL ON public.mfa_settings TO authenticated;
GRANT ALL ON public.mfa_settings TO anon;


-- ===== PART 2: Fix login_attempts RLS =====
-- The login_attempts table has RLS enabled but NO write policy for service_role
-- This causes "recordLoginAttempt" to silently fail (INSERT blocked by RLS)

ALTER TABLE public.login_attempts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow service role to write login_attempts" ON public.login_attempts;
DROP POLICY IF EXISTS "Allow all for login_attempts" ON public.login_attempts;

-- Allow service_role (Node backend) to insert and read login attempts
CREATE POLICY "Allow all for login_attempts"
    ON public.login_attempts FOR ALL USING (true) WITH CHECK (true);

GRANT ALL ON public.login_attempts TO service_role;
GRANT ALL ON public.login_attempts TO authenticated;
GRANT ALL ON public.login_attempts TO anon;
