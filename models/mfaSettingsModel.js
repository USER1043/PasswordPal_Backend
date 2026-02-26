// models/mfaSettingsModel.js
// Data access layer for the mfa_settings table.
// Replaces the old pattern of storing MFA data in the users table columns.

import { supabase } from "../config/db.js";

/**
 * Get MFA settings for a user.
 * Returns the TOTP status and encrypted secrets without exposing raw hashes.
 *
 * @param {string} userId - UUID of the user.
 * @returns {Promise<import('../validators/schemas.js').MfaSetting|null>}
 * @throws {Error} If the database query fails.
 */
export async function getMfaSettings(userId) {
    const { data, error } = await supabase
        .from("mfa_settings")
        .select("user_id, totp_secret_enc, is_totp_enabled, backup_codes_enc, codes_used, updated_at")
        .eq("user_id", userId)
        .single();

    if (error) {
        // PGRST116 = no rows found — not an error, just no MFA configured yet
        if (error.code === 'PGRST116') return null;
        throw new Error(`Error fetching MFA settings: ${error.message}`);
    }

    return data;
}

/**
 * Create or update MFA settings for a user (upsert).
 *
 * @param {Object} params
 * @param {string} params.userId - UUID of the user.
 * @param {string|null} [params.totpSecretEnc] - Encrypted TOTP secret.
 * @param {boolean} [params.isTotpEnabled] - Whether TOTP is enabled.
 * @param {string|null} [params.backupCodesEnc] - Encrypted backup codes blob.
 * @param {number} [params.codesUsed] - Count of consumed backup codes.
 * @returns {Promise<import('../validators/schemas.js').MfaSetting>}
 * @throws {Error} If the database operation fails.
 */
export async function upsertMfaSettings({ userId, totpSecretEnc, isTotpEnabled, backupCodesEnc, codesUsed }) {
    const record = {
        user_id: userId,
        updated_at: new Date().toISOString(),
    };

    if (totpSecretEnc !== undefined) record.totp_secret_enc = totpSecretEnc;
    if (isTotpEnabled !== undefined) record.is_totp_enabled = isTotpEnabled;
    if (backupCodesEnc !== undefined) record.backup_codes_enc = backupCodesEnc;
    if (codesUsed !== undefined) record.codes_used = codesUsed;

    const { data, error } = await supabase
        .from("mfa_settings")
        .upsert(record, { onConflict: 'user_id' })
        .select()
        .single();

    if (error) {
        throw new Error(`Error upserting MFA settings: ${error.message}`);
    }

    return data;
}

/**
 * Disable TOTP for a user by clearing the secret and setting the flag to false.
 *
 * @param {string} userId - UUID of the user.
 * @returns {Promise<import('../validators/schemas.js').MfaSetting>}
 * @throws {Error} If the database operation fails.
 */
export async function disableMfa(userId) {
    return upsertMfaSettings({
        userId,
        totpSecretEnc: null,
        isTotpEnabled: false,
    });
}

/**
 * Increment the codes_used counter after consuming a backup code.
 *
 * @param {string} userId - UUID of the user.
 * @returns {Promise<void>}
 * @throws {Error} If the database operation fails.
 */
export async function incrementCodesUsed(userId) {
    const current = await getMfaSettings(userId);
    if (!current) throw new Error('No MFA settings found for user');

    await upsertMfaSettings({
        userId,
        codesUsed: (current.codes_used || 0) + 1,
    });
}
