-- ============================================================================
-- Migration: allow the new failure_reason values recorded by the attempt limit
-- on /auth/recover, /auth/verify-password and /auth/change-password.
-- Run once in the Supabase SQL editor BEFORE deploying the backend change.
-- Safe to re-run.
-- ============================================================================

-- The inline CHECK from 2026-10-04_login_attempt_failure_reason.sql got the
-- default name below. Drop it and re-add it with the wider list.
ALTER TABLE public.login_attempts
    DROP CONSTRAINT IF EXISTS login_attempts_failure_reason_check;

ALTER TABLE public.login_attempts
    ADD CONSTRAINT login_attempts_failure_reason_check
    CHECK (failure_reason IN (
        'invalid_credentials',
        'device_blocked',
        'invalid_recovery_key',
        'invalid_reauth',
        'invalid_current_password'
    ));
