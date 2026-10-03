# Recovery by signature (design note)

## Problem

To prove it holds the recovery key, the app sends a fixed 64-hex fingerprint
(`hash_recovery_key`). It is the same value every time, so anyone who captures
one request (or reads it from a log or proxy) can call `/auth/recover` as often
as they like and reset the account's login.

## Design

The recovery key (the raw 32-byte vault key) deterministically yields an
Ed25519 key pair. The server stores only the public key and asks the app to
sign a fresh, one-time challenge together with the new credentials.

1. **Key pair.** `seed = BLAKE3.derive_key("passwordpal_recovery_signing_v1", mek)`;
   the Ed25519 signing key is built from that seed. The context string is
   distinct from the existing ones (`passwordpal_auth_v1`, `passwordpal_enc_v1`,
   `passwordpal_recovery_verifier_v1`), so the signing key is independent of
   every other key derived from the vault key.
2. **Registration.** The app sends `recovery_public_key` (64 hex chars, the raw
   32-byte public key). The server stores it in `recovery_keys.public_key`.
   The private key and the recovery key never leave the device.
3. **Challenge.** `POST /auth/recover/challenge { email }` returns
   `{ challenge, expires_in }`: 32 random bytes (hex), valid 5 minutes. The
   server stores only `sha256(challenge)` with the user id and expiry. The reply
   is the same shape for unknown emails and accounts without a public key
   (nothing is stored), so this endpoint does not reveal which accounts exist.
4. **Recovery.** The app signs a message built from the challenge and the new
   values, and sends `POST /auth/recover { email, challenge, signature,
   new_salt, new_wrapped_mek, new_auth_hash }`.
   Message (bytes), each field length-prefixed so no two different field
   tuples can produce the same message:

   ```
   "passwordpal-recovery-v1\n"
   then for each of challenge, new_salt, new_wrapped_mek, new_auth_hash:
       <byte length in decimal> ":" <value> "\n"
   ```
5. **Verification** (`crypto.verify(null, message, publicKey, signature)`,
   Node's built-in Ed25519): signature must verify against the stored public
   key, then the challenge is **consumed** with a single atomic
   `DELETE ... WHERE challenge_hash = ? AND user_id = ? AND expires_at > now()`
   that must remove exactly one row. A second use of the same challenge (even
   concurrently) removes nothing and is refused.

## What this fixes

| Attack | Result |
| --- | --- |
| Replay a captured `/auth/recover` request | Fails: its challenge is already consumed |
| Re-use a captured signature with different new credentials | Fails: signature covers `new_salt`, `new_wrapped_mek`, `new_auth_hash` |
| Use an expired challenge | Fails |
| Sign someone else's challenge / challenge for another account | Fails: challenge row is bound to the user |
| Steal the database | Public keys only; they cannot sign |

## Schema (migration required)

- `recovery_keys.public_key TEXT` (new). `key_hash` becomes nullable and is no
  longer read or written (kept so existing rows are not dropped).
- New `recovery_challenges (challenge_hash PK, user_id, expires_at, created_at)`,
  backend-only (RLS on, no policies, `service_role` only).

## Existing accounts

Their stored `key_hash` is a hash of the old fingerprint; the public key cannot
be derived from it, and the server never has the recovery key. They have **no
public key**, so recovery is refused for them (`404`, "no recovery key on file")
until they are re-enrolled. The owner decides: wipe the database, or add a
re-enrol step (not part of this PR, because enrolling needs the user to be
logged in with the vault unlocked).

## Out of scope

- Rate limiting of the new challenge endpoint and recovery (see the attempt-limit
  PR; apply the same helper once both are merged).
- Account enumeration through `/auth/recover` 404s (unchanged).
