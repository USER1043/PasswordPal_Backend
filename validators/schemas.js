// validators/schemas.js
// Joi validation schemas and JSDoc typedefs for all database entities.
// Aligned with the current PostgreSQL schema (Zero-Knowledge, Offline-First architecture).

import Joi from 'joi';

// ============================================================================
// JSDoc Type Definitions (for IDE Intellisense)
// ============================================================================

/**
 * @typedef {Object} User
 * @property {string} id - UUID primary key.
 * @property {string} email - Unique email address.
 * @property {string} salt - Base64 encoded salt for Argon2id key derivation.
 * @property {string} server_hash - Argon2 hash of the client's AuthHash.
 * @property {string} wrapped_mek - Master Encryption Key wrapped with KEK (Base64).
 * @property {Object} kdf_params - Key derivation function parameters.
 * @property {string} kdf_params.algo - Algorithm name (e.g. "argon2id").
 * @property {number} kdf_params.m - Memory cost in KiB (e.g. 65536).
 * @property {number} kdf_params.t - Time cost / iterations (e.g. 3).
 * @property {number} kdf_params.p - Parallelism factor (e.g. 4).
 * @property {string} vault_signature - SHA-256 hash of record_id:version pairs for sync verification.
 * @property {string} created_at - ISO 8601 creation timestamp.
 * @property {string} updated_at - ISO 8601 last-update timestamp.
 */

/**
 * @typedef {Object} VaultRecord
 * @property {string} id - UUID primary key (usually client-generated).
 * @property {string} user_id - UUID of the owning user.
 * @property {string} encrypted_data - Base64 encoded AES-GCM encrypted JSON blob.
 * @property {string} nonce - Base64 encoded IV for AES-GCM.
 * @property {number} version - Optimistic locking version counter.
 * @property {boolean} is_deleted - Soft-delete flag for tombstone sync.
 * @property {string} record_type - One of 'credential', 'folder', 'tag'.
 * @property {string|null} client_record_id - Optional client-side UUID reference.
 * @property {string} created_at - ISO 8601 creation timestamp.
 * @property {string} updated_at - ISO 8601 last-update timestamp.
 */

/**
 * @typedef {Object} UserDevice
 * @property {string} id - UUID primary key.
 * @property {string} user_id - UUID of the owning user.
 * @property {string} device_name - Human-readable device name.
 * @property {string} device_fingerprint - Unique device fingerprint hash.
 * @property {string} last_login - ISO 8601 timestamp of last login from this device.
 * @property {string|null} refresh_token - Hashed or encrypted refresh token.
 * @property {boolean} is_revoked - Whether the device session has been revoked.
 * @property {string|null} revoked_at - ISO 8601 timestamp of revocation.
 * @property {string} token_expires_at - ISO 8601 timestamp when the device token expires.
 * @property {string|null} last_country - Country code from the last login IP geolocation.
 * @property {string} created_at - ISO 8601 creation timestamp.
 * @property {string|null} trusted_until - ISO 8601 timestamp until which the device is trusted (skips MFA).
 */

/**
 * @typedef {Object} MfaSetting
 * @property {string} user_id - UUID of the user (primary key / foreign key).
 * @property {string|null} totp_secret_enc - Server-side encrypted TOTP secret.
 * @property {boolean} is_totp_enabled - Whether TOTP MFA is currently active.
 * @property {string|null} backup_codes_enc - Encrypted backup codes blob.
 * @property {number} codes_used - Count of backup codes consumed.
 * @property {string} updated_at - ISO 8601 last-update timestamp.
 */

/**
 * @typedef {Object} RecoveryKey
 * @property {string} user_id - UUID of the user.
 * @property {string} key_hash - Argon2/bcrypt hash of the recovery key.
 * @property {string} created_at - ISO 8601 creation timestamp.
 * @property {string|null} expires_at - ISO 8601 expiry timestamp, null if non-expiring.
 */

/**
 * @typedef {Object} RefreshToken
 * @property {string} id - UUID primary key.
 * @property {string} user_id - UUID of the owning user.
 * @property {string} token_hash - SHA-256 hash of the refresh token value.
 * @property {string|null} device_id - UUID of the associated device, if any.
 * @property {string} expires_at - ISO 8601 token expiry timestamp.
 * @property {boolean} is_revoked - Whether the token has been revoked.
 * @property {string|null} created_ip - IP address that created/requested the token.
 * @property {string|null} replaced_by_token_id - UUID of the token that replaced this one (rotation).
 */

/**
 * @typedef {Object} LoginAttempt
 * @property {string} id - UUID primary key.
 * @property {string|null} user_id - UUID of the target user (null if user not found).
 * @property {string} ip_address - IP address of the login attempt.
 * @property {string} attempt_time - ISO 8601 timestamp of the attempt.
 * @property {boolean} was_successful - Whether the login attempt succeeded.
 * @property {string|null} user_agent - Browser/client User-Agent string.
 */

/**
 * @typedef {Object} SyncQueueItem
 * @property {string} id - UUID primary key.
 * @property {string} user_id - UUID of the owning user.
 * @property {string|null} device_id - UUID of the originating device.
 * @property {string} record_id - UUID of the vault record being synced.
 * @property {string} operation_type - One of 'INSERT', 'UPDATE', 'DELETE'.
 * @property {string|null} encrypted_data - Encrypted payload for the operation.
 * @property {number|null} version_at_time_of_edit - Record version when the edit was made.
 * @property {string} created_at - ISO 8601 timestamp when queued.
 * @property {string|null} processed_at - ISO 8601 timestamp when processed, null if pending.
 * @property {number} retry_count - Number of times this sync operation has been retried.
 */

/**
 * @typedef {Object} Conflict
 * @property {string} id - UUID primary key.
 * @property {string} user_id - UUID of the owning user.
 * @property {string} record_id - UUID of the conflicting vault record.
 * @property {number|null} server_version - Version on the server at conflict time.
 * @property {number|null} local_version - Version on the client at conflict time.
 * @property {string|null} conflict_data_enc - Encrypted snapshot of the conflicting data.
 * @property {string|null} resolved_at - ISO 8601 resolution timestamp.
 * @property {string|null} resolution_type - One of 'SERVER_WINS', 'CLIENT_WINS', 'MANUAL_MERGE'.
 */

/**
 * @typedef {Object} AuditLog
 * @property {string} id - UUID primary key.
 * @property {string|null} user_id - UUID of the user who performed the action.
 * @property {string} event_type - Identifier for the event (e.g. 'LOGIN', 'VAULT_UPDATE').
 * @property {string|null} ip_address - IP address of the originating request.
 * @property {string|null} device_id - UUID of the device used.
 * @property {string|null} location_city - Approximate city from IP geolocation.
 * @property {Object|null} metadata - Arbitrary JSON metadata about the event.
 * @property {string} created_at - ISO 8601 timestamp of the event.
 */

// ============================================================================
// Shared Helpers
// ============================================================================

const uuid = Joi.string().uuid({ version: 'uuidv4' });
const isoDate = Joi.date().iso();

// ============================================================================
// Joi Validation Schemas
// ============================================================================

// ---------------------------------------------------------------------------
// 1. users
// ---------------------------------------------------------------------------
export const userSchema = Joi.object({
    id: uuid.optional(),
    email: Joi.string().email().required(),
    salt: Joi.string().required(),
    server_hash: Joi.string().required(),
    wrapped_mek: Joi.string().required(),
    kdf_params: Joi.object({
        algo: Joi.string().default('argon2id'),
        m: Joi.number().integer().default(65536),
        t: Joi.number().integer().default(3),
        p: Joi.number().integer().default(4),
    }).default({ algo: 'argon2id', m: 65536, t: 3, p: 4 }),
    vault_signature: Joi.string().required().default('EMPTY_VAULT'),
    created_at: isoDate.optional(),
    updated_at: isoDate.optional(),
});

// ---------------------------------------------------------------------------
// 2. vault_records
// ---------------------------------------------------------------------------
export const vaultRecordSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.required(),
    encrypted_data: Joi.string().required(),
    nonce: Joi.string().required(),
    version: Joi.number().integer().min(1).default(1),
    is_deleted: Joi.boolean().default(false),
    record_type: Joi.string().valid('credential', 'folder', 'tag').required(),
    client_record_id: Joi.string().uuid().allow(null).optional(),
    created_at: isoDate.optional(),
    updated_at: isoDate.optional(),
});

// ---------------------------------------------------------------------------
// 3. user_devices
// ---------------------------------------------------------------------------
export const userDeviceSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.required(),
    device_name: Joi.string().required(),
    device_fingerprint: Joi.string().required(),
    last_login: isoDate.optional(),
    refresh_token: Joi.string().allow(null).optional(),
    is_revoked: Joi.boolean().default(false),
    revoked_at: isoDate.allow(null).optional(),
    token_expires_at: isoDate.required(),
    last_country: Joi.string().allow(null).optional(),
    created_at: isoDate.optional(),
    trusted_until: isoDate.allow(null).optional(),
});

// ---------------------------------------------------------------------------
// 4. mfa_settings
// ---------------------------------------------------------------------------
export const mfaSettingSchema = Joi.object({
    user_id: uuid.required(),
    totp_secret_enc: Joi.string().allow(null).optional(),
    is_totp_enabled: Joi.boolean().default(false),
    backup_codes_enc: Joi.string().allow(null).optional(),
    codes_used: Joi.number().integer().min(0).default(0),
    updated_at: isoDate.optional(),
});

// ---------------------------------------------------------------------------
// 5. recovery_keys
// ---------------------------------------------------------------------------
export const recoveryKeySchema = Joi.object({
    user_id: uuid.required(),
    key_hash: Joi.string().required(),
    created_at: isoDate.optional(),
    expires_at: isoDate.allow(null).optional(),
});

// ---------------------------------------------------------------------------
// 6. refresh_tokens
// ---------------------------------------------------------------------------
export const refreshTokenSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.required(),
    token_hash: Joi.string().required(),
    device_id: uuid.allow(null).optional(),
    expires_at: isoDate.required(),
    is_revoked: Joi.boolean().default(false),
    created_ip: Joi.string().ip().allow(null).optional(),
    replaced_by_token_id: uuid.allow(null).optional(),
});

// ---------------------------------------------------------------------------
// 7. login_attempts
// ---------------------------------------------------------------------------
export const loginAttemptSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.allow(null).optional(),
    ip_address: Joi.string().ip().required(),
    attempt_time: isoDate.optional(),
    was_successful: Joi.boolean().required(),
    user_agent: Joi.string().allow(null).optional(),
});

// ---------------------------------------------------------------------------
// 8. sync_queue
// ---------------------------------------------------------------------------
export const syncQueueSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.required(),
    device_id: uuid.allow(null).optional(),
    record_id: uuid.required(),
    operation_type: Joi.string().valid('INSERT', 'UPDATE', 'DELETE').required(),
    encrypted_data: Joi.string().allow(null).optional(),
    version_at_time_of_edit: Joi.number().integer().min(0).allow(null).optional(),
    created_at: isoDate.optional(),
    processed_at: isoDate.allow(null).optional(),
    retry_count: Joi.number().integer().min(0).default(0),
});

// ---------------------------------------------------------------------------
// 9. conflicts
// ---------------------------------------------------------------------------
export const conflictSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.required(),
    record_id: uuid.required(),
    server_version: Joi.number().integer().min(1).allow(null).optional(),
    local_version: Joi.number().integer().min(1).allow(null).optional(),
    conflict_data_enc: Joi.string().allow(null).optional(),
    resolved_at: isoDate.allow(null).optional(),
    resolution_type: Joi.string()
        .valid('SERVER_WINS', 'CLIENT_WINS', 'MANUAL_MERGE')
        .allow(null)
        .optional(),
});

// ---------------------------------------------------------------------------
// 10. audit_logs
// ---------------------------------------------------------------------------
export const auditLogSchema = Joi.object({
    id: uuid.optional(),
    user_id: uuid.allow(null).optional(),
    event_type: Joi.string().required(),
    ip_address: Joi.string().ip().allow(null).optional(),
    device_id: uuid.allow(null).optional(),
    location_city: Joi.string().allow(null).optional(),
    metadata: Joi.object().allow(null).optional(),
    created_at: isoDate.optional(),
});

// ============================================================================
// Sync API Request Schemas
// ============================================================================

// ---------------------------------------------------------------------------
// GET /api/vault/sync — query params
// ---------------------------------------------------------------------------
export const pullSyncQuerySchema = Joi.object({
    since: isoDate.default(new Date(0).toISOString()),  // Defaults to epoch (full sync)
    limit: Joi.number().integer().min(1).max(500).default(100),
    offset: Joi.number().integer().min(0).default(0),
});

// ---------------------------------------------------------------------------
// POST /api/vault/sync — request body
// ---------------------------------------------------------------------------
const pushRecordItemSchema = Joi.object({
    id: uuid.required(),
    encrypted_data: Joi.string().required(),
    nonce: Joi.string().required(),
    client_known_version: Joi.number().integer().min(0).required(),
    is_deleted: Joi.boolean().default(false),
    record_type: Joi.string().valid('credential', 'folder', 'tag').default('credential'),
});

export const pushSyncBodySchema = Joi.object({
    records: Joi.array().items(pushRecordItemSchema).min(1).required(),
});
