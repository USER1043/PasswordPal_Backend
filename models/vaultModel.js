// models/vaultModel.js
// Data access layer for vault_records table.
// Uses Supabase client for queries and RPC for optimistic-locking updates.

import { supabase } from "../config/db.js";

/**
 * Retrieve all vault records for a specific user.
 * Returns an array of encrypted vault record objects from the vault_records table.
 *
 * @param {string} userId - The UUID of the user.
 * @returns {Promise<import('../validators/schemas.js').VaultRecord[]>} Array of vault records.
 * @throws {Error} If the database query fails.
 */
export async function getVaultItemsByUserId(userId) {
    const { data, error } = await supabase
        .from("vault_records")
        .select("id, user_id, encrypted_data, nonce, version, is_deleted, record_type, client_record_id, created_at, updated_at")
        .eq("user_id", userId)
        .order("updated_at", { ascending: true });

    if (error) {
        throw new Error(`Error fetching vault records: ${error.message}`);
    }

    return data || [];
}

/**
 * Create a new vault record for a user.
 * Inserts a row into the vault_records table with version 1.
 *
 * @param {Object} params
 * @param {string} params.userId - UUID of the owning user.
 * @param {string} params.encryptedData - Base64 encoded AES-GCM encrypted JSON blob.
 * @param {string} params.nonce - Base64 encoded IV for AES-GCM.
 * @param {string} params.recordType - One of 'credential', 'folder', 'tag'.
 * @param {string} [params.id] - Optional client-generated UUID for the record.
 * @param {string} [params.clientRecordId] - Optional client-side reference UUID.
 * @returns {Promise<import('../validators/schemas.js').VaultRecord>} The created vault record.
 * @throws {Error} If the database insert fails.
 */
export async function createVaultItem({ userId, encryptedData, nonce, recordType, id, clientRecordId }) {
    const record = {
        user_id: userId,
        encrypted_data: encryptedData,
        nonce: nonce,
        record_type: recordType,
        version: 1,
        is_deleted: false,
    };

    // Allow client-generated UUIDs
    if (id) record.id = id;
    if (clientRecordId) record.client_record_id = clientRecordId;

    const { data, error } = await supabase
        .from("vault_records")
        .insert([record])
        .select()
        .single();

    if (error) {
        throw new Error(`Error creating vault record: ${error.message}`);
    }

    return data;
}

/**
 * Update a vault record using the `update_vault_record` Supabase RPC.
 * Implements optimistic locking — the update is rejected if the server version
 * has advanced beyond the client's known version.
 *
 * @param {Object} params
 * @param {string} params.id - UUID of the vault record to update.
 * @param {string} params.encryptedData - New Base64 encoded encrypted data.
 * @param {string} params.nonce - New Base64 encoded IV.
 * @param {number} params.clientKnownVersion - The version the client last saw.
 * @returns {Promise<{ success: boolean, new_version: number|null, server_current_version: number }>}
 *   - `success`: true if the update was applied, false if a version conflict occurred.
 *   - `new_version`: the new version number after update (null on conflict).
 *   - `server_current_version`: the current version on the server.
 * @throws {Error} If the RPC call itself fails (network, DB error, etc.).
 */
export async function updateVaultRecord({ id, encryptedData, nonce, clientKnownVersion }) {
    const { data, error } = await supabase.rpc('update_vault_record', {
        p_id: id,
        p_encrypted_data: encryptedData,
        p_nonce: nonce,
        p_client_known_version: clientKnownVersion,
    });

    if (error) {
        throw new Error(`Error calling update_vault_record RPC: ${error.message}`);
    }

    // RPC returns: { success: boolean, new_version: number, server_current_version: number }
    return data;
}

/**
 * Soft-delete a vault record by setting is_deleted = true.
 * Performs a direct update that also bumps the version counter to maintain
 * consistency with the optimistic-locking scheme.
 *
 * @param {Object} params
 * @param {string} params.id - UUID of the vault record to delete.
 * @param {number} [params.clientKnownVersion] - The version the client last saw (optional).
 * @returns {Promise<import('../validators/schemas.js').VaultRecord>}
 * @throws {Error} If the database update fails.
 */
export async function deleteVaultRecord({ id, clientKnownVersion }) {
    // Fetch current version so we can bump it safely
    const { data: existing, error: fetchError } = await supabase
        .from("vault_records")
        .select("version")
        .eq("id", id)
        .single();

    if (fetchError) {
        throw new Error(`Error fetching record for deletion: ${fetchError.message}`);
    }

    const { data, error } = await supabase
        .from("vault_records")
        .update({
            is_deleted: true,
            version: existing.version + 1,
            updated_at: new Date().toISOString(),
        })
        .eq("id", id)
        .select()
        .single();

    if (error) {
        throw new Error(`Error soft-deleting vault record: ${error.message}`);
    }

    return data;
}

// ---------------------------------------------------------------------------
// Compatibility shims for the Story 7.1 vaultController (feature/nandan)
// These wrap the richer model functions above so the controller can call a
// simpler upsert/delete API without needing to know about the RPC layer.
// ---------------------------------------------------------------------------

/**
 * Create or update a vault record (upsert semantics).
 * If `id` is provided the record is updated via the optimistic-locking RPC
 * (using the supplied `version` as clientKnownVersion).
 * If `id` is omitted a fresh record is created via `createVaultItem`.
 *
 * @param {Object} params
 * @param {string} params.userId
 * @param {string} [params.id] - ID of the record to update (omit to create).
 * @param {string} params.encryptedData - The encrypted content.
 * @param {string} params.nonce - The encryption nonce.
 * @param {number} [params.version=1] - Version number used as clientKnownVersion on update.
 * @returns {Promise<object>} The saved vault record.
 */
export async function upsertVaultItem({ userId, id, encryptedData, nonce, version = 1 }) {
    if (id) {
        // Update path — go through the RPC for optimistic locking
        const result = await updateVaultRecord({
            id,
            encryptedData,
            nonce,
            clientKnownVersion: version,
        });
        // RPC returns { success, new_version, server_current_version }.
        // Return a shape compatible with what the controller expects.
        return result;
    }

    // Create path — no record_type available from the simple controller, default to 'credential'
    return createVaultItem({ userId, encryptedData, nonce, recordType: 'credential' });
}

/**
 * Soft-delete a vault record (simple signature used by vaultController).
 *
 * @param {string} userId - UUID of the owning user (used for additional security check).
 * @param {string} recordId - UUID of the record to delete.
 * @returns {Promise<object>} The updated vault record.
 */
export async function deleteVaultItem(userId, recordId) {
    // Verify ownership before deletion
    const { data: record, error: ownerCheckError } = await supabase
        .from("vault_records")
        .select("id")
        .eq("id", recordId)
        .eq("user_id", userId)
        .single();

    if (ownerCheckError || !record) {
        throw new Error(`Record not found or access denied.`);
    }

    return deleteVaultRecord({ id: recordId });
}
