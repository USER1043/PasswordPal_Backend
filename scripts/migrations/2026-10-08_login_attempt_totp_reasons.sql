-- ============================================================================
-- Migration: allow the failure_reason values recorded by the attempt limit on
-- the two-factor code check (/auth/totp/verify-login) and backup-code redeem.
-- Run once in the Supabase SQL editor BEFORE deploying the backend change.
-- Safe to re-run.
-- ============================================================================

ALTER TABLE public.login_attempts
    DROP CONSTRAINT IF EXISTS login_attempts_failure_reason_check;

ALTER TABLE public.login_attempts
    ADD CONSTRAINT login_attempts_failure_reason_check
    CHECK (failure_reason IN (
        'invalid_credentials',
        'device_blocked',
        'invalid_recovery_key',
        'invalid_reauth',
        'invalid_current_password',
        'invalid_totp_code',
        'invalid_backup_code'
    ));
