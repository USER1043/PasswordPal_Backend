# Security policy

PasswordPal is a password manager, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem. Report it privately using GitHub's [private vulnerability reporting](https://github.com/USER1043/PasswordPal_Backend/security/advisories/new) for this repository, and include:

- what you found and which endpoint or file is affected
- steps or a request that reproduces it
- the impact you think it has

You can expect an acknowledgement within a few days. Please give us reasonable time to fix the issue before disclosing it.

## Supported versions

Only the latest commit on `main` is supported. There are no long-lived release branches.

## Scope

In scope: authentication and session handling, account recovery, 2FA, rate limiting, vault storage and sync, device management, and database access control.

Out of scope: denial of service by sheer volume, social engineering, and issues that need a compromised user device or a leaked server secret.

## Security model in brief

- The server never receives the master password. It stores an Argon2id hash of a client-derived `auth_hash`, and an encrypted vault it cannot read.
- Sessions are device-bound `HttpOnly` cookies. Revoking or blocking a device invalidates its session.
- Failed password, code and recovery attempts share a per-IP limit of 5 per 15 minutes.
- TOTP codes are single-use and refuse replay. Account recovery requires an Ed25519 signature over a one-time challenge.
- Row Level Security is enabled on all tables and the public database roles are locked out.

The detail, and a list of known limitations, is in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

## Known limitations

These are documented openly so contributors can help close them:

- Refresh-token rotation does not detect reuse of an old token.
- Disabling and re-enabling 2FA does not clear trusted devices.
- `POST /auth/totp/verify-setup` is not covered by the shared rate limit.
- `GET /auth/params` and `POST /auth/recover` answer `404` for unknown accounts, so they reveal whether an email is registered.
- The shared limit is per IP, so users behind one address share one budget.
- `/api/favicon` is unauthenticated and not rate limited.
