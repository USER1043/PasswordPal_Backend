-- ============================================================================
-- Migration: device_events - history of revoke / block / unblock actions
-- Run once in the Supabase SQL editor. Safe to re-run.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.device_events (
    id                 UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id            UUID        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    action             TEXT        NOT NULL CHECK (action IN ('revoke', 'block', 'unblock')),
    target_device_id   UUID        REFERENCES public.user_devices(id) ON DELETE SET NULL,
    target_device_name TEXT        NOT NULL,       -- Snapshot, so history survives device deletion
    actor_device_id    UUID        REFERENCES public.user_devices(id) ON DELETE SET NULL,
    actor_device_name  TEXT        NOT NULL,       -- Device the action was performed from
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log query pattern: a user's events, newest first
CREATE INDEX IF NOT EXISTS idx_device_events_user ON public.device_events (user_id, created_at DESC);

-- Backend-only table: RLS on with no policies, so only the service role can read or write it
ALTER TABLE public.device_events ENABLE ROW LEVEL SECURITY;
GRANT ALL ON public.device_events TO service_role;
