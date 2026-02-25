// models/refreshTokenModel.js
// Data access layer for the refresh_tokens table.
// Manages token lifecycle: creation, rotation, revocation, and validation.

import { supabase } from "../config/db.js";

/**
 * Store a new refresh token record.
 *
 * @param {Object} params
 * @param {string} params.userId - UUID of the owning user.
 * @param {string} params.tokenHash - SHA-256 hash of the token value. Never store raw tokens.
 * @param {string|null} [params.deviceId] - UUID of the associated device.
 * @param {Date|string} params.expiresAt - When the token expires (ISO 8601).
 * @param {string|null} [params.createdIp] - IP address that requested the token.
 * @returns {Promise<import('../validators/schemas.js').RefreshToken>}
 * @throws {Error} If the database insert fails.
 */
export async function createRefreshToken({ userId, tokenHash, deviceId = null, expiresAt, createdIp = null }) {
    const { data, error } = await supabase
        .from("refresh_tokens")
        .insert([{
            user_id: userId,
            token_hash: tokenHash,
            device_id: deviceId,
            expires_at: expiresAt,
            created_ip: createdIp,
            is_revoked: false,
        }])
        .select("id, user_id, device_id, expires_at, is_revoked, created_ip, created_at")
        .single();

    if (error) {
        throw new Error(`Error creating refresh token: ${error.message}`);
    }

    // Never return the token_hash in responses
    return data;
}

/**
 * Find a refresh token by its hash. Used during token verification.
 * Only returns non-revoked, non-expired tokens.
 *
 * @param {string} tokenHash - SHA-256 hash of the token to look up.
 * @returns {Promise<import('../validators/schemas.js').RefreshToken|null>}
 * @throws {Error} If the database query fails.
 */
export async function findValidRefreshToken(tokenHash) {
    const { data, error } = await supabase
        .from("refresh_tokens")
        .select("id, user_id, device_id, expires_at, is_revoked, created_ip, replaced_by_token_id")
        .eq("token_hash", tokenHash)
        .eq("is_revoked", false)
        .gt("expires_at", new Date().toISOString())
        .single();

    if (error) {
        if (error.code === 'PGRST116') return null; // No rows found
        throw new Error(`Error finding refresh token: ${error.message}`);
    }

    return data;
}

/**
 * Revoke a refresh token (e.g., on logout or rotation).
 * Optionally records which new token replaced it (for rotation tracking).
 *
 * @param {string} tokenId - UUID of the token to revoke.
 * @param {string|null} [replacedByTokenId] - UUID of the replacement token.
 * @returns {Promise<void>}
 * @throws {Error} If the database update fails.
 */
export async function revokeRefreshToken(tokenId, replacedByTokenId = null) {
    const update = { is_revoked: true };
    if (replacedByTokenId) update.replaced_by_token_id = replacedByTokenId;

    const { error } = await supabase
        .from("refresh_tokens")
        .update(update)
        .eq("id", tokenId);

    if (error) {
        throw new Error(`Error revoking refresh token: ${error.message}`);
    }
}

/**
 * Revoke all refresh tokens for a user (e.g., on password change or security event).
 *
 * @param {string} userId - UUID of the user.
 * @returns {Promise<void>}
 * @throws {Error} If the database update fails.
 */
export async function revokeAllUserTokens(userId) {
    const { error } = await supabase
        .from("refresh_tokens")
        .update({ is_revoked: true })
        .eq("user_id", userId)
        .eq("is_revoked", false);

    if (error) {
        throw new Error(`Error revoking all user tokens: ${error.message}`);
    }
}
