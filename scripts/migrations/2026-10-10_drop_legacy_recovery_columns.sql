-- Recovery now relies on an Ed25519 signature checked against recovery_keys.public_key.
-- key_hash (hash of the old replayable fingerprint) and expires_at (never set) are no longer
-- read or written, so remove them.
ALTER TABLE public.recovery_keys
    DROP COLUMN IF EXISTS key_hash,
    DROP COLUMN IF EXISTS expires_at;
