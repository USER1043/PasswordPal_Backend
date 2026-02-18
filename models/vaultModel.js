import { supabase } from "../config/db.js";

/**
 * Retrieve all vault records for a specific user.
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<Array>} - Array of vault records { id, encrypted_data, nonce, version, updated_at }
 */
export async function getVaultItemsByUserId(userId) {
    const { data, error } = await supabase
        .from("vault_records")
        .select("id, encrypted_data, nonce, version, updated_at, is_deleted")
        .eq("user_id", userId)
        .eq("is_deleted", false); // Assuming we don't want deleted items by default

    if (error) {
        throw new Error(`Error fetching vault records: ${error.message}`);
    }

    return data || [];
}

/**
 * Create or Update a vault record.
 * @param {object} params
 * @param {string} params.userId
 * @param {string} [params.id] - ID of the record to update (optional, new ID generated if missing)
 * @param {string} params.encryptedData - The encrypted content
 * @param {string} params.nonce - The encryption nonce
 * @param {number} [params.version] - Version number for concurrency/sync
 */
export async function upsertVaultItem({ userId, id, encryptedData, nonce, version = 1 }) {
    const payload = {
        user_id: userId,
        encrypted_data: encryptedData,
        nonce: nonce,
        version: version,
        updated_at: new Date().toISOString(),
        is_deleted: false
    };

    // If ID is provided, include it in the payload for upsert to match on PK
    if (id) {
        payload.id = id;
    }

    const { data, error } = await supabase
        .from("vault_records")
        .upsert(payload)
        .select()
        .single();

    if (error) {
        throw new Error(`Error saving vault record: ${error.message}`);
    }

    return data;
}

/**
 * Soft delete a vault record.
 * @param {string} userId 
 * @param {string} recordId 
 */
export async function deleteVaultItem(userId, recordId) {
    const { data, error } = await supabase
        .from("vault_records")
        .update({ is_deleted: true, updated_at: new Date().toISOString() })
        .eq("id", recordId)
        .eq("user_id", userId) // Security: ensure user owns the record
        .select()
        .single();

    if (error) {
        throw new Error(`Error deleting vault record: ${error.message}`);
    }
    return data;
}
