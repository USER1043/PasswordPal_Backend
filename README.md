# PasswordPal Backend

The sync and account API for [PasswordPal](https://github.com/USER1043/PasswordPal_Frontend), a zero-knowledge, local-first password manager. It is a Node.js + Express service backed by Supabase (PostgreSQL).

The server never receives the master password or any key that can decrypt a vault. It stores encrypted blobs, a hash of a client-derived authentication key, and metadata (devices, login history, 2FA settings). See [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for exactly what the server can and cannot see.

## Features

- **Zero-knowledge accounts.** Register and log in with a client-derived `auth_hash`. The server stores only an Argon2id hash of it (`server_hash`) and the client-wrapped master key (`wrapped_mek`).
- **Device-bound sessions.** Access (15 min) and refresh (7 days) JWTs live in `HttpOnly` cookies and carry a device id. Revoking or blocking a device ends its session on the next request.
- **Two-factor authentication.** TOTP (RFC 6238) with single-use codes and one-time backup codes, plus an optional 30-day "trust this device".
- **Signature-based account recovery.** The recovery key never leaves the app. Recovery needs an Ed25519 signature over a one-time challenge. See [docs/RECOVERY_SIGNATURE_DESIGN.md](docs/RECOVERY_SIGNATURE_DESIGN.md).
- **Brute-force protection.** A shared per-IP limit of 5 failed attempts per 15 minutes across login, recovery, re-authentication, password change and 2FA checks.
- **Encrypted vault storage and delta sync** with optimistic version locking, soft deletes and conflict responses.
- **Device management and audit log** (login history, device revoke/block events).
- **Privacy proxies** for breach checks (k-anonymity prefix lookup) and favicons, so the client never contacts those services directly.
- **Locked-down database.** Row Level Security is enabled on every table and `anon`/`authenticated` roles have no access. Only the backend's service key reads or writes data.

## Tech stack

| Area | Choice |
| :--- | :--- |
| Runtime / framework | Node.js (ESM), Express 5 |
| Database | PostgreSQL on Supabase (`@supabase/supabase-js`) |
| Auth | `jsonwebtoken`, `argon2`, `cookie-parser` |
| 2FA | `speakeasy`, `qrcode` |
| Validation | Joi |
| Config | `@dotenvx/dotenvx` |
| Tests | Vitest, Supertest |

## Getting started

### Prerequisites

- Node.js 20 or newer (CI uses 24)
- A Supabase project

### Setup

```bash
git clone https://github.com/USER1043/PasswordPal_Backend.git
cd PasswordPal_Backend
npm install
cp .env.example .env     # then fill in the values
```

1. In the Supabase SQL editor, run `scripts/init_db.sql` on an empty project. It creates every table, index, grant and RLS policy at the latest schema. For an existing project, run the files in `scripts/migrations/` that you have not applied yet, in filename order.
2. Use the **secret / service_role** key for `SUPABASE_SECRET_KEY`. The publishable (anon) key will not work, because the tables are closed to that role.
3. Generate the secrets:

   ```bash
   openssl rand -hex 32   # JWT_SECRET
   openssl rand -hex 32   # ENCRYPTION_KEY
   ```

### Run

```bash
npm run dev     # nodemon, restarts on change
npm start       # production-style start
```

The API listens on `http://localhost:3000` by default. `GET /health` returns `204` when the database is reachable and `503` otherwise.

### Test

```bash
npm test        # vitest run: unit and route tests, no database needed
```

Tests mock Supabase, so they run offline. See [CONTRIBUTING.md](CONTRIBUTING.md) for how the mocks are written.

## Configuration

All variables are listed in [.env.example](.env.example).

| Variable | Required | Purpose |
| :--- | :--- | :--- |
| `SUPABASE_URL` | yes | Supabase project URL |
| `SUPABASE_SECRET_KEY` | yes | Supabase secret (service role) key |
| `JWT_SECRET` | yes | Signs access, refresh and MFA-pending tokens |
| `ENCRYPTION_KEY` | yes | Encrypts TOTP secrets at rest. The server refuses to start in production without it |
| `PORT` | no | Listen port, default `3000` |
| `NODE_ENV` | no | `production` turns on `Secure`/`SameSite=None` cookies and disables dev-only routes |
| `FRONTEND_URL` | no | Extra allowed CORS origin, default `http://localhost:5173` (the Tauri origins are always allowed) |
| `TRUST_PROXY_HOPS` | no | Number of reverse proxies in front of the app. Used to find the real client IP for rate limiting and the audit log. Default `0` |

## Scripts

| Command | What it does |
| :--- | :--- |
| `npm run dev` | Start with `nodemon` and `.env` loaded by dotenvx |
| `npm start` | Start with `node` |
| `npm test` | Run the Vitest suite |
| `npm run keep-alive` | Run a trivial query to stop a free-tier Supabase project from pausing |

The `scripts/` folder also contains one-off helpers (schema inspection, manual MFA and lockout checks, HTML demos). They are served at `/scripts` outside production only and are not part of the API.

## API overview

| Prefix | Purpose |
| :--- | :--- |
| `/auth` | Register, login, refresh, logout, re-authentication, recovery, password change |
| `/auth/totp` | 2FA setup, login verification, backup codes, disable |
| `/api/vault` | Vault CRUD and delta sync |
| `/api/devices` | List, revoke, block, unblock devices |
| `/api/audit-logs` | Login history and device events |
| `/api/breach`, `/api/favicon` | Privacy-preserving proxies |
| `/api/export`, `/api/delete-account` | Sensitive actions that need a fresh password check |

The full reference, with request bodies and error codes, is in [docs/API.md](docs/API.md).

## Project layout

```
app.js            Express app: middleware, CORS, routes, health check
server.js         Entry point
config/db.js      Supabase client and database health polling
route/            URL -> middleware -> controller wiring
controllers/      Request handling and responses
models/           Database access (one file per table or concern)
middleware/       verifySession, requireFreshAuth
validators/       Joi schemas and the validation middleware
utils/            Sessions, rate limiting, TOTP, recovery signature, encryption
scripts/          init_db.sql, migrations/, dev helpers
tests/            Vitest suites
docs/             Design and reference documents
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md): layers, request flow, session lifecycle
- [Security model](docs/SECURITY_MODEL.md): what is protected, how, and known limitations
- [API reference](docs/API.md)
- [Database](docs/DATABASE.md): tables, relationships, migrations
- [Recovery by signature](docs/RECOVERY_SIGNATURE_DESIGN.md)
- [Contributing](CONTRIBUTING.md) and [Security policy](SECURITY.md)

## Deployment

`render.yaml` describes a Render web service (`npm ci`, `npm start`, health check on `/health`). Set the variables from the table above in the Render dashboard. Behind Render's proxy, keep `TRUST_PROXY_HOPS=1`.

## License

ISC
