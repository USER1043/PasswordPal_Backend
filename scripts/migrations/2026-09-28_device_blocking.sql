-- ============================================================================
-- Migration: per-device sessions, device blocking, device ID on login attempts
-- Run once in the Supabase SQL editor. Safe to re-run.
-- ============================================================================

ALTER TABLE public.user_devices   ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE public.user_devices   ADD COLUMN IF NOT EXISTS blocked_at TIMESTAMPTZ;
ALTER TABLE public.login_attempts ADD COLUMN IF NOT EXISTS device_id  TEXT;

-- device_fingerprint now holds the raw client device UUID. Retire legacy rows
-- whose fingerprint was a server-side sha256 hash - those installs re-register
-- under their UUID on next login.
UPDATE public.user_devices
   SET is_revoked = TRUE, revoked_at = NOW()
 WHERE is_revoked = FALSE
   AND device_fingerprint !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

-- verifySession / refresh: per-request device check as an index-only scan
CREATE INDEX IF NOT EXISTS idx_user_devices_session
    ON public.user_devices (id, user_id) INCLUDE (is_revoked, is_blocked);

-- Suspicious-login tracking: attempts per device over time
CREATE INDEX IF NOT EXISTS idx_login_attempts_device
    ON public.login_attempts (device_id, attempt_time DESC)
    WHERE device_id IS NOT NULL;
