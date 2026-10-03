-- ============================================================================
-- Migration: record why a login attempt failed, so the audit log can tell a
-- login refused for a blocked device apart from a wrong password.
-- Run once in the Supabase SQL editor. Safe to re-run.
-- ============================================================================

-- NULL for successful attempts and for failures recorded before this migration.
ALTER TABLE public.login_attempts
    ADD COLUMN IF NOT EXISTS failure_reason TEXT
    CHECK (failure_reason IN ('invalid_credentials', 'device_blocked'));
