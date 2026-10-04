-- ============================================================================
-- Migration: remember the latest TOTP step used to log in, so a code cannot be
-- used twice. Run once in the Supabase SQL editor BEFORE deploying the backend
-- change. Safe to re-run. Existing rows get NULL, meaning "nothing used yet".
-- ============================================================================

ALTER TABLE public.mfa_settings ADD COLUMN IF NOT EXISTS last_used_step BIGINT;
