-- ============================================================================
-- Migration: signature-based account recovery.
-- Run once in the Supabase SQL editor BEFORE deploying the backend change.
-- Safe to re-run.
--
-- Existing accounts: their recovery data (key_hash, a hash of the old
-- replayable fingerprint) cannot be turned into a public key, so they have
-- public_key = NULL and CANNOT recover until re-enrolled (or the database is
-- wiped). Nothing here deletes data.
-- ============================================================================

ALTER TABLE public.recovery_keys ADD COLUMN IF NOT EXISTS public_key TEXT;

-- New registrations no longer write key_hash
ALTER TABLE public.recovery_keys ALTER COLUMN key_hash DROP NOT NULL;

CREATE TABLE IF NOT EXISTS public.recovery_challenges (
    challenge_hash TEXT        PRIMARY KEY,
    user_id        UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    expires_at     TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recovery_challenges_user ON public.recovery_challenges (user_id, expires_at);

-- Backend-only table: RLS on with no policies, so only the service role can read or write it
ALTER TABLE public.recovery_challenges ENABLE ROW LEVEL SECURITY;
GRANT ALL ON public.recovery_challenges TO service_role;
