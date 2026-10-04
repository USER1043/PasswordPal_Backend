-- ============================================================================
-- Migration: only the backend (service_role) may touch the database.
-- Run once in the Supabase SQL editor. Safe to re-run. Deletes no data.
--
-- Why: the "Allow all" policies and the grants to anon/authenticated meant
-- anyone holding the project's public (anon) key could read and write
-- login_attempts, recovery_keys, mfa_settings, refresh_tokens, sync_queue and
-- conflicts directly through Supabase's REST API, bypassing the backend.
-- The two vault functions are SECURITY DEFINER and executable by PUBLIC, so the
-- same key could also call them and overwrite any user's vault record.
--
-- The backend uses the service-role key (SUPABASE_SECRET_KEY), which bypasses
-- RLS and keeps its grants, so it is unaffected. CONFIRM that variable holds the
-- service_role key and not the anon key before running this, or the backend
-- will lose access.
-- ============================================================================

-- 1. Drop the open policies. RLS stays ON, so a table with no policy denies
--    everyone except service_role.
DROP POLICY IF EXISTS "Allow all for login_attempts"  ON public.login_attempts;
DROP POLICY IF EXISTS "Allow all for recovery_keys"   ON public.recovery_keys;
DROP POLICY IF EXISTS "Allow all for mfa_settings"    ON public.mfa_settings;
DROP POLICY IF EXISTS "Allow all for refresh_tokens"  ON public.refresh_tokens;
DROP POLICY IF EXISTS "Allow all for sync_queue"      ON public.sync_queue;
DROP POLICY IF EXISTS "Allow all for conflicts"       ON public.conflicts;

-- The user-scoped policies (users, vault_records, user_devices) test auth.uid(),
-- which only exists for Supabase Auth logins; this app issues its own JWTs, so
-- they never match anyone. They are left in place and are inert once the grants
-- below are revoked.

-- 2. Revoke every table privilege from the public-facing roles; keep service_role.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;
GRANT  ALL ON ALL TABLES IN SCHEMA public TO service_role;

-- 3. The vault functions: no longer callable by PUBLIC/anon/authenticated.
--    Matched by name so it works whatever their exact signature is in your database.
DO $$
DECLARE
    fn regprocedure;
BEGIN
    FOR fn IN
        SELECT p.oid::regprocedure
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'public'
          AND p.proname IN ('atomic_upsert_vault_record', 'update_vault_record')
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon, authenticated', fn);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', fn);
    END LOOP;
END $$;

-- 4. Make it stick for objects created later by this role (the SQL editor runs as
--    postgres): new tables and functions are not handed to the public-facing roles.
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM anon, authenticated;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM PUBLIC, anon, authenticated;

-- ----------------------------------------------------------------------------
-- Check afterwards (both should come back with no rows):
--
--   SELECT tablename, policyname FROM pg_policies
--   WHERE schemaname = 'public' AND qual = 'true';
--
--   SELECT table_name, grantee, privilege_type
--   FROM information_schema.role_table_grants
--   WHERE table_schema = 'public' AND grantee IN ('anon', 'authenticated');
-- ----------------------------------------------------------------------------
