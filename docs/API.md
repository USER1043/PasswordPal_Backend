# API reference

Base URL: `http://localhost:3000` in development. All bodies are JSON unless noted. Errors look like `{ "error": "message", "code": "OPTIONAL_CODE" }`.

## Conventions

- **Auth** column: `none`, `session` (valid access cookie, `verifySession`), `fresh` (session plus a password check in the last 5 minutes, `requireFreshAuth`) or `mfa` (the 5-minute pending cookie issued after the password step).
- **`X-Device-Id` header.** `POST /auth/login` requires the app's per-install UUID in this header, or it returns `400 DEVICE_ID_REQUIRED`. The same header is read when a session is issued after 2FA.
- **Cookies.** Session endpoints read `sb-access-token`; `/auth/refresh` reads `sb-refresh-token`. Both are `HttpOnly`, so clients send them with credentials enabled.
- **Validation.** Routes with a Joi schema return `400` with details for malformed input.
- **Offline signal.** If the API cannot reach its database, `/api` and `/auth` routes (except logout) return `503`.

### Error codes

| Status | Code | Meaning |
| :--- | :--- | :--- |
| 400 | `DEVICE_ID_REQUIRED` | Missing or malformed `X-Device-Id` |
| 401 | `SESSION_REVOKED` | The session's device was revoked or blocked, or the session cannot be renewed. Sign in again |
| 401 | `MFA_SESSION_EXPIRED` | The 5-minute 2FA step expired. Start the login again |
| 401 | `TOTP_CODE_REUSED` | That authenticator code (or an earlier one) was already used |
| 401 | `INVALID_CODE` | Wrong code when disabling 2FA |
| 401 | `INVALID_CURRENT_PASSWORD` | Wrong current password on password change |
| 401 | `CHALLENGE_INVALID` | Recovery challenge is unknown, expired or already used |
| 403 | `DEVICE_BLOCKED` | This device is blocked from the account |
| 403 | `REAUTH_REQUIRED` | Call `POST /auth/verify-password`, then retry |
| 429 | | Too many failed attempts (5 per IP per 15 minutes, shared) |
| 503 | | Database unreachable |

## Health

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| GET | `/health` | none | `204` if the database is reachable, `503` otherwise |
| GET | `/` | none | Plain-text liveness message |

## Accounts and sessions (`/auth`)

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| POST | `/auth/register` | none | Create an account. Body: `email`, `salt`, `wrapped_mek`, `auth_hash`, `recovery_public_key` (64 hex). `201`, or `409` if the email exists |
| GET | `/auth/params?email=` | none | Returns `{ salt }` so the app can derive its keys. `404` for an unknown email |
| POST | `/auth/login` | none | Body: `email`, `auth_hash`. Needs `X-Device-Id`. Returns `{ user, wrapped_mek, salt, trusted_device }` and sets cookies, or `{ mfa_required: true }` with a pending cookie when 2FA applies. `401` on bad credentials, `403 DEVICE_BLOCKED`, `429` |
| POST | `/auth/refresh` | refresh cookie | Issues new cookies. `401 SESSION_REVOKED` if the device is revoked or blocked |
| POST | `/auth/logout` | none | Clears cookies and revokes the device the refresh token belongs to |
| POST | `/auth/verify-password` | session | Body: `auth_hash`. Marks the session fresh. Counts failures against the limiter |
| POST | `/auth/change-password` | session | Body: `salt`, `wrapped_mek`, `auth_hash` (new) and `current_auth_hash`. Signs out all other devices and clears trusted devices. `401 INVALID_CURRENT_PASSWORD` |
| POST | `/auth/recover/challenge` | none | Body: `email`. Returns `{ challenge, expires_in }` (same shape for unknown accounts) |
| POST | `/auth/recover` | none | Body: `email`, `challenge` (64 hex), `signature` (128 hex), `new_salt`, `new_wrapped_mek` (base64), `new_auth_hash` (64 hex). Verifies the Ed25519 signature, updates credentials and revokes all devices. See [RECOVERY_SIGNATURE_DESIGN.md](RECOVERY_SIGNATURE_DESIGN.md) |

## Two-factor authentication (`/auth/totp`)

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| POST | `/auth/totp/setup` | session | Returns a new `secret`, `qrCode` (data URL) and `otpauth_url`. Nothing is stored yet |
| POST | `/auth/totp/verify-setup` | session | Body: `secret`, `code`. Confirms the code, stores the encrypted secret, enables 2FA and returns `backupCodes` |
| GET | `/auth/totp/status` | session | `{ totp_enabled }` |
| POST | `/auth/totp/verify-login` | mfa | Body: `code` (6 digits), optional `trust_device`. Completes login and returns `{ user, wrapped_mek, salt, ... }`. `401 TOTP_CODE_REUSED`, `401 MFA_SESSION_EXPIRED`, `429` |
| POST | `/auth/totp/backup-codes/redeem` | mfa | Body: `code`. Completes login with a one-time backup code |
| POST | `/auth/totp/backup-codes/generate` | session | New backup codes (invalidates the old set). `?download=1` returns plain text |
| POST | `/auth/totp/disable` | session | Body: `code` (authenticator code or unused backup code). `401 INVALID_CODE` |

In development only, `POST /auth/totp/dev/backup-codes/generate` exists for local testing.

## Vault (`/api`)

All vault routes need a session. Records are opaque to the server.

| Method | Path | Description |
| :--- | :--- | :--- |
| GET | `/api/vault` | All records for the user: `{ items, count }` |
| GET | `/api/vault/:id` | One record: `{ item }`. `404` if missing |
| POST | `/api/vault` | Create or update. Body: `encrypted_data`, `nonce`, optional `id`, `version` (the version last seen; `0` for new), `record_type` (`credential`, `folder`, `tag`). `409` with `server_version` on a version conflict |
| DELETE | `/api/vault/:id` | Soft-delete a record |
| GET | `/api/vault/sync` | Delta pull. Query: `since` (ISO time, default epoch), `limit` (1-500, default 100), `offset`. Returns `{ records, total_count, has_more, server_time }` |
| POST | `/api/vault/sync` | Batch push. Body: `records[]` of `{ id, encrypted_data, nonce, client_known_version, is_deleted, record_type }`. Returns `{ results[], server_time }` where each result has a `status` of `success`, `created`, `conflict` or `error` |
| GET | `/api/vault-data` | Legacy combined payload: `{ user, items }` |

## Devices and audit

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| GET | `/api/devices` | session | The user's devices, with `isCurrent` set for the calling device |
| POST | `/api/devices/register` | session | Body: `name`. Sets the display name of the calling device (the device row itself is created at login) |
| POST | `/api/devices/:id/revoke` | session | End that device's session |
| POST | `/api/devices/:id/block` | session | Block a device (`400` for the device in use) |
| POST | `/api/devices/:id/unblock` | session | Remove a block |
| GET | `/api/audit-logs?limit=&offset=` | session | `{ logs, device_events, total, total_success, total_failed, limit, offset }`. `limit` defaults to 50, max 100 |

## Sensitive actions (need `fresh`)

| Method | Path | Description |
| :--- | :--- | :--- |
| POST | `/api/export` | Returns `{ exported_at, record_count, records }` (still encrypted) |
| DELETE | `/api/delete-account` | Permanently deletes the account and its data |

## Privacy proxies

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| GET | `/api/breach/:prefix` | session | Proxies Pwned Passwords. `prefix` is 5 hex characters; the response is the plain-text suffix list |
| GET | `/api/favicon?domain=` | none | Returns a 32px favicon image for the domain |
